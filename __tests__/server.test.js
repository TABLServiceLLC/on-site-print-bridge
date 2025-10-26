const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const jwt = require('jsonwebtoken');

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

  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'testsecret';
  process.env.PRINTER_MAP_FILE = mapFile;

  const { app } = require('../server');
  const token = jwt.sign({ sub: 'tester' }, process.env.JWT_SECRET);
  const auth = { Authorization: `Bearer ${token}` };

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

  test('GET /printers triggers discovery on refresh without auth', async () => {
    const res = await request(app).get('/printers?refresh=true').expect(200);
    expect(res.body).toHaveProperty('printers');
    expect(res.body.printers.length).toBe(1);
    expect(res.body.printers[0].ip).toBe('192.168.1.100');
  });
});
