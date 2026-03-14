# NetSentry dashboard

The dashboard uses native JavaScript modules, so serve the repository over HTTP instead of opening `index.html` as a `file://` URL.

To start the API, dashboard, and capture pipeline together from the repository root:

```powershell
python run.py "Wi-Fi"
```

The argument may be an interface IP, PCAP name, system name, or human-readable name.

To run only the dashboard file server:

From the repository root:

```powershell
python api/dashboard_server.py
```

Then open <http://127.0.0.1:8080/dashboard/>. The API remains at `http://127.0.0.1:8000` and the live packet stream at `http://127.0.0.1:8765`.

## Structure

- `index.html` — panel markup
- `css/dashboard.css` — shared styling
- `js/app.js` — startup and navigation
- `js/api.js` — API endpoints and operator identity
- One JavaScript module per dashboard feature
