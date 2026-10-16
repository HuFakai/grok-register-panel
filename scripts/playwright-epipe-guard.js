'use strict';

/**
 * Playwright 1.60 ships Node 24. When the browser/Python pipe closes,
 * PipeTransport.send() emits an unhandled Socket 'error' (EPIPE) and
 * Node 24 kills the driver — taking the whole register batch with it.
 *
 * Loaded via `node --require` from scripts/playwright-node.
 */

function isPipeErr(err) {
  if (!err) return false;
  const code = err.code || err.errno;
  const msg = String(err.message || err);
  return (
    code === 'EPIPE' ||
    code === 'ECONNRESET' ||
    code === 'ERR_STREAM_DESTROYED' ||
    code === -32 ||
    msg.includes('EPIPE') ||
    msg.includes('ECONNRESET')
  );
}

try {
  const net = require('net');
  const origEmit = net.Socket.prototype.emit;
  net.Socket.prototype.emit = function patchedEmit(type, ...args) {
    if (type === 'error' && this.listenerCount('error') === 0 && isPipeErr(args[0])) {
      return false;
    }
    return origEmit.call(this, type, ...args);
  };
} catch (_e) {
  /* ignore */
}

process.on('uncaughtException', (err) => {
  if (isPipeErr(err)) return;
  throw err;
});

process.on('unhandledRejection', (err) => {
  if (isPipeErr(err)) return;
});
