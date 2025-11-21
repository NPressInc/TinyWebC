/**
 * Byte order conversion utilities - mirrors backend byteorder.c
 * Provides network byte order (big-endian) conversion functions
 */

/**
 * Convert 64-bit integer to network byte order (big-endian)
 * @param {bigint} value - The value to convert
 * @returns {bigint} - Value in network byte order
 */
export function htonll(value) {
  // JavaScript DataView always uses big-endian when false parameter is used
  // But we need to manually handle 64-bit conversion
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);

  // Write in host byte order (little-endian on most systems)
  view.setBigUint64(0, value, true);

  // Read back as big-endian
  return view.getBigUint64(0, false);
}

/**
 * Convert 64-bit integer from network byte order (big-endian) to host byte order
 * @param {bigint} value - The value in network byte order
 * @returns {bigint} - Value in host byte order
 */
export function ntohll(value) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);

  // Write as big-endian
  view.setBigUint64(0, value, false);

  // Read back in host byte order
  return view.getBigUint64(0, true);
}
