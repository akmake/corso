import { exec } from 'child_process';

export const hasDwgConverter = () =>
  new Promise((resolve) => {
    exec('libreoffice --version', (err) => resolve(!err));
  });
