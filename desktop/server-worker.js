import { parentPort } from 'node:worker_threads';
import { createServer } from '../server.js';

const server = createServer();
server.on('error', (error) => parentPort?.postMessage({ type: 'error', message: error.message }));
server.listen(0, '127.0.0.1', () => {
  parentPort?.postMessage({ type: 'ready', port: server.address().port });
});

parentPort?.on('message', (message) => {
  if (message?.type === 'stop') server.close(() => parentPort.close());
});
