import React, { useState, useEffect } from 'react';
import './LocationDashboard.css';
import { detectRunningNodes, getUsers, getLocation, getLocationHistory, submitLocation, DEFAULT_NODE_URLS } from '../utils/api';
import { createSignedClientRequest } from '../utils/clientRequestHelper';
import { encryptPayloadMulti } from '../utils/encryption';
import keyStore from '../utils/keystore';
import sodium from 'libsodium-wrappers';

function LocationDashboard() {
  const [selectedNode, setSelectedNode] = useState('');
  const [availableNodes, setAvailableNodes] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedUser, setSelectedUser] = useState(null);
  const [location, setLocation] = useState(null);
  const [locationHistory, setLocationHistory] = useState([]);
  const [showSubmitForm, setShowSubmitForm] = useState(false);
  const [submitForm, setSubmitForm] = useState({
    lat: '',
    lon: '',
    accuracy_m: '10',
    location_name: '',
  });

  useEffect(() => {
    loadNodes();
  }, []);

  useEffect(() => {
    if (selectedNode) {
      loadUsers();
    }
  }, [selectedNode]);

  useEffect(() => {
    if (selectedUser && selectedNode) {
      loadLocation();
      loadLocationHistory();
    }
  }, [selectedUser, selectedNode]);

  const loadNodes = async () => {
    try {
      const nodes = await detectRunningNodes();
      setAvailableNodes(nodes);
      if (nodes.length > 0) {
        setSelectedNode(nodes[0].url);
      }
    } catch (err) {
      console.error('Error detecting nodes:', err);
      setError('Failed to detect running nodes');
    }
  };

  const loadUsers = async () => {
    if (!selectedNode) return;
    
    setLoading(true);
    setError(null);
    try {
      await keyStore.init();
      if (!keyStore.isKeypairLoaded()) {
        setError('No keypair loaded. Please load or generate keys first.');
        setLoading(false);
        return;
      }

      const response = await getUsers(selectedNode);
      if (response.users) {
        setUsers(response.users);
      }
    } catch (err) {
      console.error('Error loading users:', err);
      setError(`Failed to load users: ${err.message}`);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  const loadLocation = async () => {
    if (!selectedUser || !selectedNode) return;
    
    try {
      const loc = await getLocation(selectedNode, selectedUser.pubkey);
      setLocation(loc);
    } catch (err) {
      console.error('Error loading location:', err);
      setLocation(null);
    }
  };

  const loadLocationHistory = async () => {
    if (!selectedUser || !selectedNode) return;
    
    try {
      const history = await getLocationHistory(selectedNode, selectedUser.pubkey, 50, 0);
      setLocationHistory(history);
    } catch (err) {
      console.error('Error loading location history:', err);
      setLocationHistory([]);
    }
  };

  const handleSubmitLocation = async (e) => {
    e.preventDefault();
    if (!selectedNode) {
      setError('Please select a node');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await sodium.ready;
      await keyStore.init();
      if (!keyStore.isKeypairLoaded()) {
        throw new Error('No keypair loaded. Please load or generate keys first.');
      }

      const senderPubkey = keyStore.getPublicKey();
      
      // For location updates, recipients are typically parents/admins who should see the location
      // For now, we'll use the sender as the only recipient (self)
      // In a real scenario, you'd select recipients (e.g., parent pubkeys)
      const recipients = [senderPubkey];

      const locationUpdate = {
        lat: parseFloat(submitForm.lat),
        lon: parseFloat(submitForm.lon),
        accuracy_m: parseInt(submitForm.accuracy_m) || 10,
        timestamp: Math.floor(Date.now() / 1000),
        location_name: submitForm.location_name || '',
      };

      // Create and sign ClientRequest
      const clientRequest = await createSignedClientRequest(
        locationUpdate,
        recipients,
        encryptPayloadMulti
      );

      // Submit to node
      await submitLocation(selectedNode, clientRequest);

      // Reset form
      setSubmitForm({
        lat: '',
        lon: '',
        accuracy_m: '10',
        location_name: '',
      });
      setShowSubmitForm(false);

      // Reload location data
      if (selectedUser) {
        await loadLocation();
        await loadLocationHistory();
      }
    } catch (err) {
      console.error('Error submitting location:', err);
      setError(`Failed to submit location: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
  };

  return (
    <div className="location-dashboard">
      <h1>Location Tracking Dashboard</h1>

      {/* Node Selection */}
      <div className="node-selection">
        <label>
          Select Node:
          <select 
            value={selectedNode} 
            onChange={(e) => setSelectedNode(e.target.value)}
            disabled={loading}
          >
            <option value="">-- Select Node --</option>
            {availableNodes.map((node) => (
              <option key={node.url} value={node.url}>
                {node.nodeId} ({node.url})
              </option>
            ))}
          </select>
        </label>
        <button onClick={loadNodes} disabled={loading}>
          Refresh Nodes
        </button>
      </div>

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      {selectedNode && (
        <>
          {/* User Selection */}
          <div className="user-selection">
            <h2>Users</h2>
            {loading ? (
              <p>Loading users...</p>
            ) : (
              <div className="user-list">
                {users.map((user) => (
                  <div
                    key={user.pubkey}
                    className={`user-item ${selectedUser?.pubkey === user.pubkey ? 'selected' : ''}`}
                    onClick={() => setSelectedUser(user)}
                  >
                    <div className="user-name">{user.username || 'Unknown'}</div>
                    <div className="user-pubkey">{user.pubkey.substring(0, 16)}...</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Location Display */}
          {selectedUser && (
            <div className="location-display">
              <h2>Location for {selectedUser.username || 'Unknown'}</h2>
              
              {location ? (
                <div className="location-info">
                  <div className="location-field">
                    <strong>Latitude:</strong> {location.lat}
                  </div>
                  <div className="location-field">
                    <strong>Longitude:</strong> {location.lon}
                  </div>
                  <div className="location-field">
                    <strong>Accuracy:</strong> {location.accuracy_m}m
                  </div>
                  <div className="location-field">
                    <strong>Timestamp:</strong> {formatTimestamp(location.timestamp)}
                  </div>
                  {location.location_name && (
                    <div className="location-field">
                      <strong>Location Name:</strong> {location.location_name}
                    </div>
                  )}
                  <div className="location-map-link">
                    <a
                      href={`https://www.google.com/maps?q=${location.lat},${location.lon}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View on Google Maps
                    </a>
                  </div>
                </div>
              ) : (
                <p>No location data available</p>
              )}

              {/* Location History */}
              <div className="location-history">
                <h3>Location History</h3>
                {locationHistory.length > 0 ? (
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Latitude</th>
                        <th>Longitude</th>
                        <th>Accuracy</th>
                        <th>Location Name</th>
                      </tr>
                    </thead>
                    <tbody>
                      {locationHistory.map((loc, idx) => (
                        <tr key={idx}>
                          <td>{formatTimestamp(loc.timestamp)}</td>
                          <td>{loc.lat}</td>
                          <td>{loc.lon}</td>
                          <td>{loc.accuracy_m}m</td>
                          <td>{loc.location_name || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p>No location history available</p>
                )}
              </div>
            </div>
          )}

          {/* Submit Location Form */}
          <div className="submit-location">
            <button onClick={() => setShowSubmitForm(!showSubmitForm)}>
              {showSubmitForm ? 'Hide' : 'Submit'} Location Update
            </button>

            {showSubmitForm && (
              <form onSubmit={handleSubmitLocation} className="submit-form">
                <h3>Submit Location Update</h3>
                <div className="form-group">
                  <label>
                    Latitude:
                    <input
                      type="number"
                      step="any"
                      value={submitForm.lat}
                      onChange={(e) => setSubmitForm({ ...submitForm, lat: e.target.value })}
                      required
                    />
                  </label>
                </div>
                <div className="form-group">
                  <label>
                    Longitude:
                    <input
                      type="number"
                      step="any"
                      value={submitForm.lon}
                      onChange={(e) => setSubmitForm({ ...submitForm, lon: e.target.value })}
                      required
                    />
                  </label>
                </div>
                <div className="form-group">
                  <label>
                    Accuracy (meters):
                    <input
                      type="number"
                      value={submitForm.accuracy_m}
                      onChange={(e) => setSubmitForm({ ...submitForm, accuracy_m: e.target.value })}
                      required
                    />
                  </label>
                </div>
                <div className="form-group">
                  <label>
                    Location Name (optional):
                    <input
                      type="text"
                      value={submitForm.location_name}
                      onChange={(e) => setSubmitForm({ ...submitForm, location_name: e.target.value })}
                      placeholder="Home, School, etc."
                    />
                  </label>
                </div>
                <button type="submit" disabled={loading}>
                  {loading ? 'Submitting...' : 'Submit Location'}
                </button>
              </form>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default LocationDashboard;

