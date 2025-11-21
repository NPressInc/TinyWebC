const path = require('path');

module.exports = function override(config, env) {
  // Suppress Node.js module warnings - libsodium-wrappers handles browser compatibility internally
  config.resolve.fallback = {
    ...config.resolve.fallback,
    crypto: false,
    stream: false,
    buffer: false,
    process: false,
  };

  return config;
};
