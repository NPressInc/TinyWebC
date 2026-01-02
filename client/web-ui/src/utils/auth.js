/**
 * Authentication state management
 * Note: Flat architecture - any node can serve requests
 * For now, we use the first node from DEFAULT_NODE_URLS
 */

import { DEFAULT_NODE_URLS } from './api';

const AUTH_STORAGE_KEY = 'tinyweb_logged_in';
const USER_PUBKEY_KEY = 'tinyweb_user_pubkey';
const NODE_URL_KEY = 'tinyweb_node_url';

// Get default node URL (first node in list - can be made smarter later)
export function getDefaultNodeUrl() {
  return Object.values(DEFAULT_NODE_URLS)[0] || 'http://localhost:8000';
}

export function isAuthenticated() {
  return localStorage.getItem(AUTH_STORAGE_KEY) === 'true';
}

export function getUserPubkey() {
  return localStorage.getItem(USER_PUBKEY_KEY);
}

export function getNodeUrl() {
  // Return stored node URL, or fall back to default (first node)
  return localStorage.getItem(NODE_URL_KEY) || getDefaultNodeUrl();
}

export function setAuthState(pubkey, nodeUrl) {
  localStorage.setItem(AUTH_STORAGE_KEY, 'true');
  localStorage.setItem(USER_PUBKEY_KEY, pubkey);
  localStorage.setItem(NODE_URL_KEY, nodeUrl);
}

export function clearAuthState() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
  localStorage.removeItem(USER_PUBKEY_KEY);
  localStorage.removeItem(NODE_URL_KEY);
}

