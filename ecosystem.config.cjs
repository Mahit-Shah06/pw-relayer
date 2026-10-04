module.exports = {
  apps: [{
    name: 'pw-relayer',
    cwd: __dirname,
    script: './start.mjs',
    interpreter: 'node',
    node_args: '--env-file=.env',
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,
    restart_delay: 3000,
    kill_timeout: 20000,
    time: true,
    env: { NODE_ENV: 'production', HOST: '127.0.0.1', PORT: '8080' }
  }]
};
