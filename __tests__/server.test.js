const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const net = require('net');
const { EventEmitter } = require('events');

// Mock discoverPrinters before requiring server to control scanning
jest.mock('../discoverPrinters.js', () => ({
  scanNetwork: jest.fn(async () => [
    { ip: '192.168.1.100', openPorts: [9100], mac: 'aa:bb:cc:dd:ee:ff' }
  ]),
  defaultCidrFromInterfaces: () => '192.168.1.0/24'
}), { virtual: false });

describe('server endpoints', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pb-server-'));
  const mapFile = path.join(tmpDir, 'printerMap.json');
  const labelsFile = path.join(tmpDir, 'printerLabels.json');
  const globalPrintersFile = path.join(tmpDir, 'globalPrinters.json');

  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'testsecret';
  process.env.PRINTER_MAP_FILE = mapFile;
  process.env.PRINTER_LABELS_FILE = labelsFile;
  process.env.GLOBAL_PRINTERS_FILE = globalPrintersFile;

  const serverModule = require('../server');
  const { app } = serverModule;
  const token = jwt.sign({ sub: 'tester' }, process.env.JWT_SECRET);
  const auth = { Authorization: `Bearer ${token}` };
  const xAuth = { 'X-Authorization': `Bearer ${token}` };

  test('GET /health is ok', async () => {
    await request(app).get('/health').expect(200);
  });

  test('POST /assign validates IP', async () => {
    const res = await request(app).post('/assign').set(auth).send({ terminalId: 't1', ip: 'bad-ip' });
    expect(res.status).toBe(400);
  });

  test('POST /assign stores mapping', async () => {
    const res = await request(app).post('/assign').set(auth).send({ terminalId: 't2', ip: '192.168.1.55' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(mapFile, 'utf8'));
    expect(onDisk['t2']).toBe('192.168.1.55');
  });

  test('POST /assign accepts X-Authorization header', async () => {
    const res = await request(app).post('/assign').set(xAuth).send({ terminalId: 't3', ip: '192.168.1.56' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(mapFile, 'utf8'));
    expect(onDisk['t3']).toBe('192.168.1.56');
  });

  test('GET /printers triggers discovery on refresh without auth', async () => {
    const res = await request(app).get('/printers?refresh=true').expect(200);
    expect(res.body).toHaveProperty('printers');
    expect(res.body.printers.length).toBe(1);
    expect(res.body.printers[0].ip).toBe('192.168.1.100');
  });

  test('terminal management endpoints support CRUD', async () => {
    let res = await request(app).get('/api/terminals').set(auth);
    expect(res.status).toBe(200);
    const initialCount = Array.isArray(res.body.terminals) ? res.body.terminals.length : 0;

    res = await request(app).post('/terminals').set(auth).send({ terminalId: 'unit-1', label: 'Unit 1' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.terminal).toMatchObject({ terminalId: 'unit-1', label: 'Unit 1' });

    res = await request(app).patch('/terminals/unit-1').set(auth).send({ label: 'Unit Prime' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.terminal).toMatchObject({ terminalId: 'unit-1', label: 'Unit Prime' });

    await request(app).post('/assign').set(auth).send({ terminalId: 'unit-1', ip: '192.168.1.57' }).expect(200);

    res = await request(app).delete('/terminals/unit-1').set(auth);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.terminalId).toBe('unit-1');
    expect(res.body.removedIp).toBe('192.168.1.57');

    res = await request(app).get('/api/terminals').set(auth);
    expect(res.status).toBe(200);
    const finalTerminals = Array.isArray(res.body.terminals) ? res.body.terminals : [];
    expect(finalTerminals.length).toBe(initialCount);
    expect(finalTerminals.find((t) => t.terminalId === 'unit-1')).toBeUndefined();
  });

  test('printer management endpoints support CRUD', async () => {
    let res = await request(app).get('/api/printers').set(auth);
    expect(res.status).toBe(200);
    const initialCount = Array.isArray(res.body.printers) ? res.body.printers.length : 0;

    res = await request(app).post('/printers').set(auth).send({ ip: '192.168.1.200', label: 'Prep Station' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.printer).toMatchObject({ ip: '192.168.1.200', label: 'Prep Station' });

    res = await request(app).patch('/printers/192.168.1.200').set(auth).send({ label: 'Prep Prime' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.printer).toMatchObject({ ip: '192.168.1.200', label: 'Prep Prime' });

    await request(app).post('/terminals').set(auth).send({ terminalId: 'unit-aux', label: 'Aux' }).expect(200);
    await request(app).post('/assign').set(auth).send({ terminalId: 'unit-aux', ip: '192.168.1.200' }).expect(200);

    res = await request(app).delete('/printers/192.168.1.200').set(auth);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.removedTerminals).toContain('unit-aux');

    res = await request(app).get('/api/printers').set(auth);
    expect(res.status).toBe(200);
    const finalPrinters = Array.isArray(res.body.printers) ? res.body.printers : [];
    expect(finalPrinters.length).toBe(initialCount);
    expect(finalPrinters.find((p) => p.ip === '192.168.1.200')).toBeUndefined();

    await request(app).delete('/terminals/unit-aux').set(auth).expect(200);
  });

  test('global printer endpoints support CRUD and printing', async () => {
    const createConnectionSpy = jest.spyOn(net, 'createConnection').mockImplementation(() => {
      const socket = new EventEmitter();
      socket.bytesWritten = 0;
      socket.setTimeout = () => {};
      socket.write = (buffer, cb) => {
        socket.bytesWritten += buffer.length;
        if (typeof cb === 'function') cb();
        setImmediate(() => socket.emit('close', false));
      };
      socket.end = () => {
        setImmediate(() => socket.emit('close', false));
      };
      socket.destroy = () => {};
      setImmediate(() => socket.emit('connect'));
      return socket;
    });

    let res = await request(app).get('/api/global-printers').set(auth);
    expect(res.status).toBe(200);
    const initialCount = Array.isArray(res.body.printers) ? res.body.printers.length : 0;

    res = await request(app).post('/global-printers').set(auth).send({ printerId: 'kitchen', ip: '192.168.1.210', label: 'Kitchen' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.printer).toMatchObject({ printerId: 'kitchen', ip: '192.168.1.210', label: 'Kitchen' });

    res = await request(app).patch('/global-printers/kitchen').set(auth).send({ label: 'Kitchen Main' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.printer).toMatchObject({ printerId: 'kitchen', label: 'Kitchen Main' });

    const data = Buffer.from('test payload', 'utf8').toString('base64');
    res = await request(app).post('/print/global').set(auth).send({ printerId: 'kitchen', data });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body).toMatchObject({ printerId: 'kitchen', ip: '192.168.1.210' });
    expect(createConnectionSpy).toHaveBeenCalledWith({ host: '192.168.1.210', port: 9100 });

    res = await request(app).delete('/global-printers/kitchen').set(auth);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.printerId).toBe('kitchen');

    res = await request(app).get('/api/global-printers').set(auth);
    expect(res.status).toBe(200);
    const finalPrinters = Array.isArray(res.body.printers) ? res.body.printers : [];
    expect(finalPrinters.length).toBe(initialCount);
    expect(finalPrinters.find((p) => p.printerId === 'kitchen')).toBeUndefined();

    createConnectionSpy.mockRestore();
  });
});
