/**
 * TinyWeb Frontend Crypto Utilities
 *
 * This module provides cryptographic utilities that mirror the backend
 * keystore and encryption logic for secure messaging.
 */

export { default as keyStore } from './keystore.js';
export * from './keystore.js';

export * from './encryption.js';

// Note: envelope.js removed - client only uses Message structure for user messaging
// System messages (LocationUpdate, EmergencyAlert) are not handled by this client
export * from './message.js';

// Re-export libsodium for convenience
export { default as sodium } from 'libsodium-wrappers';
