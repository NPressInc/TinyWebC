import React, { useState, useEffect } from 'react';
import './LocationDashboard.css';
import { getUsers, getLocation, getLocationHistory, submitLocation } from '../utils/api';
import { createSignedClientRequest } from '../utils/clientRequestHelper';
import { encryptPayloadMulti } from '../utils/encryption';
import keyStore from '../utils/keystore';
import { getNodeUrl } from '../utils/auth';
import sodium from 'libsodium-wrappers';
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Fix for default marker icons in React-Leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

function LocationDashboard() {
  const [selectedNode, setSelectedNode] = useState('');
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedUser, setSelectedUser] = useState(null);
  const [location, setLocation] = useState(null);
  const [locationHistory, setLocationHistory] = useState([]);
  const [timeRangeDays, setTimeRangeDays] = useState(7); // Default to 7 days
  const [showSubmitForm, setShowSubmitForm] = useState(false);
  const [submitForm, setSubmitForm] = useState({
    lat: '',
    lon: '',
    accuracy_m: '10',
    location_name: '',
  });

  useEffect(() => {
    // Initialize with default node URL
    const defaultNode = getNodeUrl();
    setSelectedNode(defaultNode);
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
      console.log('Loading location history for user:', selectedUser.pubkey);
      const history = await getLocationHistory(selectedNode, selectedUser.pubkey, 50, 0);
      console.log('Location history received:', history);
      setLocationHistory(Array.isArray(history) ? history : []);
    } catch (err) {
      console.error('Error loading location history:', err);
      setError(`Failed to load location history: ${err.message}`);
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

  // Filter locations based on time range
  const getFilteredLocations = () => {
    if (timeRangeDays === 9999) return locationHistory; // Show all
    
    const now = Math.floor(Date.now() / 1000);
    const cutoffTime = now - (timeRangeDays * 24 * 60 * 60);
    return locationHistory.filter(loc => loc.timestamp >= cutoffTime);
  };

  // Component to auto-fit map bounds when location data changes
  const MapBounds = ({ locations }) => {
    const map = useMap();
    
    useEffect(() => {
      if (locations.length > 0) {
        const bounds = L.latLngBounds(locations.map(loc => [loc.lat, loc.lon]));
        map.fitBounds(bounds, { padding: [50, 50] });
      } else if (location) {
        map.setView([location.lat, location.lon], 13);
      }
    }, [locations, location, map]);
    
    return null;
  };

  return (
    <div className="location-dashboard">
      <h1>Location Tracking Dashboard</h1>

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
              
              {/* Time Range Filter */}
              <div className="time-filter">
                <label>
                  Show locations from last: 
                  <select 
                    value={timeRangeDays} 
                    onChange={(e) => setTimeRangeDays(Number(e.target.value))}
                  >
                    <option value={1}>1 day</option>
                    <option value={7}>7 days</option>
                    <option value={30}>30 days</option>
                    <option value={90}>90 days</option>
                    <option value={365}>1 year</option>
                    <option value={9999}>All time</option>
                  </select>
                </label>
              </div>
              
              {/* Embedded Map */}
              <div className="location-map-container">
                {(() => {
                  const filteredHistory = getFilteredLocations();
                  const hasData = location || filteredHistory.length > 0;
                  
                  return hasData ? (
                    <MapContainer
                      center={location ? [location.lat, location.lon] : [0, 0]}
                      zoom={location ? 13 : 2}
                      style={{ height: '400px', width: '100%' }}
                      scrollWheelZoom={true}
                    >
                      <TileLayer
                        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                      />
                      <MapBounds locations={location ? [location, ...filteredHistory] : filteredHistory} />
                      
                      {/* Current location marker */}
                      {location && (
                        <Marker position={[location.lat, location.lon]}>
                          <Popup>
                            <div>
                              <strong>Current Location</strong><br />
                              {location.location_name && <><strong>Name:</strong> {location.location_name}<br /></>}
                              <strong>Accuracy:</strong> {location.accuracy_m}m<br />
                              <strong>Time:</strong> {formatTimestamp(location.timestamp)}
                            </div>
                          </Popup>
                        </Marker>
                      )}
                      
                      {/* Filtered location history markers */}
                      {filteredHistory.map((loc, idx) => (
                        <Marker 
                          key={idx} 
                          position={[loc.lat, loc.lon]}
                          opacity={0.7}
                        >
                          <Popup>
                            <div>
                              <strong>{formatTimestamp(loc.timestamp)}</strong><br />
                              {loc.location_name && <><strong>Name:</strong> {loc.location_name}<br /></>}
                              <strong>Accuracy:</strong> {loc.accuracy_m}m
                            </div>
                          </Popup>
                        </Marker>
                      ))}
                      
                      {/* Path connecting filtered history points */}
                      {filteredHistory.length > 1 && (
                        <Polyline
                          positions={filteredHistory.map(loc => [loc.lat, loc.lon])}
                          color="blue"
                          opacity={0.5}
                          weight={2}
                        />
                      )}
                      
                      {/* Path from current to most recent filtered history */}
                      {location && filteredHistory.length > 0 && (
                        <Polyline
                          positions={[[location.lat, location.lon], [filteredHistory[0].lat, filteredHistory[0].lon]]}
                          color="green"
                          opacity={0.7}
                          weight={3}
                          dashArray="10, 5"
                        />
                      )}
                    </MapContainer>
                  ) : (
                    <div className="map-placeholder">
                      <p>No location data to display for selected time range</p>
                    </div>
                  );
                })()}
              </div>
              
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
                </div>
              ) : (
                <p>No location data available</p>
              )}

              {/* Location History */}
              <div className="location-history">
                <h3>Location History ({getFilteredLocations().length} locations)</h3>
                {getFilteredLocations().length > 0 ? (
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
                      {getFilteredLocations().map((loc, idx) => (
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
                  <p>No location history available for selected time range</p>
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

