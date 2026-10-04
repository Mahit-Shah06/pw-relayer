// PM2 imports this entry point through its own wrapper. Start unconditionally.
import { startServer } from './server.mjs';
await startServer();
