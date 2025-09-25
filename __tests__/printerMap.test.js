const fs = require('fs');
const os = require('os');
const path = require('path');

describe('printerMap', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'printermap-'));
  const mapFile = path.join(tmpDir, 'printerMap.json');

  beforeAll(() => {
    process.env.PRINTER_MAP_FILE = mapFile;
  });

  test('get/set printer mapping', () => {
    const map = require('../printerMap');
    expect(map.getPrinterIp('t1')).toBeUndefined();
    const updated = map.setPrinterIp('t1', '192.168.1.50');
    expect(updated['t1']).toBe('192.168.1.50');
    expect(map.getPrinterIp('t1')).toBe('192.168.1.50');
    const onDisk = JSON.parse(fs.readFileSync(mapFile, 'utf8'));
    expect(onDisk['t1']).toBe('192.168.1.50');
  });

  test('rejects invalid IP', () => {
    const map = require('../printerMap');
    expect(() => map.setPrinterIp('t2', 'not-an-ip')).toThrow();
  });
});

