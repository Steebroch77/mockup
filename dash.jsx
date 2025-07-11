import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
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
  const [mispData, setMispData] = useState(null);
  const [ctiData, setCtiData] = useState(null);
  const [vtQuery, setVtQuery] = useState('');
  const [vtData, setVtData] = useState(null);
  const [otxData, setOtxData] = useState(null);
  const [shodanData, setShodanData] = useState(null);

  const fetchData = async () => {
    const misp = await fetch('/api/misp-gcc-qatar');
    const mispJson = await misp.json();
    setMispData(mispJson);

    const cti = await fetch('/api/opencti-gcc-qatar');
    const ctiJson = await cti.json();
    setCtiData(ctiJson);

    const otx = await fetch('/api/otx-gcc-qatar');
    const otxJson = await otx.json();
    setOtxData(otxJson);

    const shodan = await fetch('/api/shodan-gcc-qatar');
    const shodanJson = await shodan.json();
    setShodanData(shodanJson);
  };

  const fetchVT = async () => {
    const vt = await fetch(`/api/virustotal?query=${encodeURIComponent(vtQuery)}`);
    const vtJson = await vt.json();
    setVtData(vtJson);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  const threatActorChartData = ctiData?.threatActors?.edges?.map(({ node }) => ({
    name: node.name,
    length: node.description?.length || 0
  }));

  const vtDetectionChartData = vtData?.data?.attributes?.last_analysis_stats
    ? Object.entries(vtData.data.attributes.last_analysis_stats).map(([key, value]) => ({ name: key, value }))
    : null;

  const otxChartData = otxData?.pulse_info?.pulses?.map(p => ({ name: p.name, indicators: p.indicator_count })) || [];

  const shodanChartData = shodanData?.map(item => ({
    ip: item.ip_str,
    ports: item.port ? 1 : 0
  })) || [];

  const shodanGeoData = shodanData?.filter(d => d.location?.latitude && d.location?.longitude) || [];

  const mispGeoData = mispData?.filter(d => d.latitude && d.longitude).map(d => ({
    latitude: d.latitude,
    longitude: d.longitude,
    info: d.info || 'MISP Event'
  })) || [];

  const vtGeoData = vtData?.data?.attributes?.location
    ? [{
        latitude: vtData.data.attributes.location.latitude,
        longitude: vtData.data.attributes.location.longitude,
        info: vtData.data.id
      }]
    : [];

  const heatPoints = [
    ...shodanGeoData.map(d => [d.location.latitude, d.location.longitude]),
    ...mispGeoData.map(d => [d.latitude, d.longitude]),
    ...vtGeoData.map(d => [d.latitude, d.longitude])
  ];

  const pieColors = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

  return (
    <div className="grid gap-6 p-6">
      <h1 className="text-3xl font-bold text-center">GCC & Qatar Threat Intelligence Dashboard</h1>
      <div className="flex justify-center gap-4">
        <input
          placeholder="Search IP / Hash / Domain"
          className="border px-3 py-2 rounded shadow"
          value={vtQuery}
          onChange={(e) => setVtQuery(e.target.value)}
        />
        <button onClick={fetchVT} className="bg-green-600 text-white px-6 py-2 rounded-2xl shadow">
          Search VirusTotal
        </button>
      </div>

      {(shodanGeoData.length > 0 || mispGeoData.length > 0 || vtGeoData.length > 0) && (
        <div className="bg-white shadow rounded-2xl p-4">
          <h2 className="text-xl font-semibold mb-4">Threat Geolocation Map</h2>
          <div className="h-[500px] w-full">
            <MapContainer center={[25.276987, 51.520008]} zoom={4} scrollWheelZoom={false} className="h-full w-full rounded-xl">
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
                      <strong>Org:</strong> {item.org || 'N/A'}<br />
                      <strong>Port:</strong> {item.port || 'N/A'}<br />
                      <strong>Location:</strong> {item.location.city || 'Unknown'}, {item.location.country_name || 'Unknown'}
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
      )}
    </div>
  );
}
