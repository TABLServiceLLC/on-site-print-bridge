const path = require('path');

// Mock child_process.execFile to simulate ping and arp outputs
jest.mock('child_process', () => {
  return {
    execFile: (cmd, args, opts, cb) => {
      // Support optional opts
      const callback = typeof cb === 'function' ? cb : (typeof opts === 'function' ? opts : () => {});
      const ipArg = Array.isArray(args) ? args[args.length - 1] : '';
      if (cmd === 'ping') {
        // all pings succeed
        setImmediate(() => callback(null, 'ok'));
        return { on: () => {} };
      }
      // ARP/ip neigh: include MAC on line with IP
      const stdout = `${ipArg} at aa:bb:cc:dd:ee:ff`;
      setImmediate(() => callback(null, stdout));
      return { on: () => {} };
    }
  };
});

// Mock net.Socket for port checks
jest.mock('net', () => {
  const EventEmitter = require('events');
  class FakeSocket extends EventEmitter {
    setTimeout() {}
    destroy() {}
    connect(port, ip) {
      setImmediate(() => {
        if (ip === '10.0.0.1' && port === 9100) this.emit('connect');
        else this.emit('error', new Error('ECONNREFUSED'));
      });
    }
  }
  return { Socket: FakeSocket };
});

describe('discoverPrinters.scanNetwork', () => {
  const modPath = path.resolve(__dirname, '../discoverPrinters.js');
  // require after mocks
  const { scanNetwork } = require(modPath);

  test('finds only hosts with 9100 open by default', async () => {
    const res = await scanNetwork({ cidr: '10.0.0.0/30', ports: [9100, 515], timeoutMs: 50, concurrency: 2 });
    expect(Array.isArray(res)).toBe(true);
    expect(res.length).toBe(1);
    expect(res[0]).toHaveProperty('ip', '10.0.0.1');
    expect(res[0].openPorts).toContain(9100);
  });

  test('includeNon9100 returns all probed hosts', async () => {
    const res = await scanNetwork({ cidr: '10.0.0.0/30', ports: [9100], timeoutMs: 50, concurrency: 2, includeNon9100: true });
    const ips = res.map(r => r.ip).sort();
    expect(ips).toEqual(['10.0.0.1', '10.0.0.2']);
  });
});

