import axios from 'axios';

const API_BASE = 'http://localhost:5000/api';

export const startScan = async (url) => {
  const response = await axios.post(`${API_BASE}/scan/start`, { url });
  return response.data;
};

export const getScanStatus = async (url) => {
  const response = await axios.get(`${API_BASE}/scan/status`, { params: { url } });
  return response.data;
};

export const getScanResults = async (url) => {
  const response = await axios.get(`${API_BASE}/scan/results`, { params: { url } });
  return response.data;
};
