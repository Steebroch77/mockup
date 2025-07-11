import { useState, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import 'leaflet.heat';

const iconColors = {
  shodan: 'blue',
  misp: 'red',
  vt: 'green'
};

function createColoredIcon(color) {
  return new L.Icon({
    iconUrl: `https://chart.googleapis.com/chart?chst=d_map_pin_icon&chld=flag|${color}`,
    iconSize: [21, 34],
    iconAnchor: [10, 34],
    popupAnchor: [1, -34]
  });
}

function HeatmapLayer({ points }) {
  const map = useMap();

  useEffect(() => {
    const heat = L.heatLayer(points, { radius: 25, blur: 15 });
    heat.addTo(map);
    return () => {
      map.removeLayer(heat);
    };
  }, [map, points]);

  return null;
}

export default function Dashboard() {
  // Mock data for preview:
  const mockMispData = [
    { latitude: 24.7136, longitude: 46.6753, info: "MISP Event Riyadh" },      // Saudi Arabia
    { latitude: 25.2854, longitude: 51.5310, info: "MISP Event Doha" },        // Qatar
  ];
  const mockShodanData = [
    {
      ip_str: "103.25.217.10",
      org: "ISP Qatar",
      port: 443,
      location: { latitude: 25.2854, longitude: 51.5310, city: "Doha", country_name: "Qatar" }
    },
    {
      ip_str: "2.50.20.7",
      org: "ISP Saudi Arabia",
      port: 80,
      location: { latitude: 24.7136, longitude: 46.6753, city: "Riyadh", country_name: "Saudi Arabia" }
    },
  ];
  const mockVtData = {
    data: {
      id: "VT-12345",
      attributes: {
        location: { latitude: 24.4539, longitude: 54.3773 }, // Abu Dhabi, UAE
        last_analysis_stats: {
          harmless: 10,
          malicious: 3,
          suspicious: 1,
          undetected: 5
        }
      }
    }
  };

  // Set mock data in state
  const [mispData] = useState(mockMispData);
  const [shodanData] = useState(mockShodanData);
  const [vtData] = useState(mockVtData);

  // Prepare geo data
  const shodanGeoData = shodanData?.filter(d => d.location?.latitude && d.location?.longitude) || [];
  const mispGeoData = mispData?.filter(d => d.latitude && d.longitude) || [];
  const vtGeoData = vtData?.data?.attributes?.location
    ? [{
        latitude: vtData.data.attributes.location.latitude,
        longitude: vtData.data.attributes.location.longitude,
        info: vtData.data.id
      }]
    : [];

  // Heatmap points: array of [lat, lon]
  const heatPoints = [
    ...shodanGeoData.map(d => [d.location.latitude, d.location.longitude]),
    ...mispGeoData.map(d => [d.latitude, d.longitude]),
    ...vtGeoData.map(d => [d.latitude, d.longitude])
  ];

  return (
    <div className="grid gap-6 p-6">
      <h1 className="text-3xl font-bold text-center">GCC & Qatar Threat Intelligence Dashboard (Mock Data Preview)</h1>

      <div className="bg-white shadow rounded-2xl p-4">
        <h2 className="text-xl font-semibold mb-4">Threat Geolocation Map</h2>
        <div className="h-[500px] w-full">
          <MapContainer center={[25.276987, 51.520008]} zoom={5} scrollWheelZoom={false} className="h-full w-full rounded-xl">
            <TileLayer
              attribution='&copy; <a href="http://osm.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            <HeatmapLayer points={heatPoints} />
            {shodanGeoData.map((item, idx) => (
              <Marker key={`shodan-${idx}`} position={[item.location.latitude, item.location.longitude]} icon={createColoredIcon(iconColors.shodan)}>
                <Popup>
                  <div className="text-sm">
                    <strong>Shodan IP:</strong> {item.ip_str}<br />
                    <strong>Org:</strong> {item.org}<br />
                    <strong>Port:</strong> {item.port}<br />
                    <strong>Location:</strong> {item.location.city}, {item.location.country_name}
                  </div>
                </Popup>
              </Marker>
            ))}
            {mispGeoData.map((item, idx) => (
              <Marker key={`misp-${idx}`} position={[item.latitude, item.longitude]} icon={createColoredIcon(iconColors.misp)}>
                <Popup>
                  <div className="text-sm">
                    <strong>MISP:</strong> {item.info}
                  </div>
                </Popup>
              </Marker>
            ))}
            {vtGeoData.map((item, idx) => (
              <Marker key={`vt-${idx}`} position={[item.latitude, item.longitude]} icon={createColoredIcon(iconColors.vt)}>
                <Popup>
                  <div className="text-sm">
                    <strong>VirusTotal:</strong> {item.info}
                  </div>
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        </div>
      </div>
    </div>
  );
}
