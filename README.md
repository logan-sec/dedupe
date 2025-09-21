# dedupe

**dedupe** is a Python tool for merging, cleaning, and normalizing subdomain lists.  
It removes duplicates, supports optional IP-based collapsing, and can probe for live hosts — making it a useful utility for bug bounty recon workflows.  

---

## ⚠️ Development Status

**dedupe is fully functional and already speeds up recon workflows,**  
but it’s still under active development. Expect ongoing improvements, new features, and refinements.  

👉 Contributions, suggestions, and feedback are always welcome!

## ✨ Features
- Merge multiple `.txt` files into a single deduplicated list  
- Normalize hostnames (removes trailing dots, converts to lowercase, etc.)  
- Optional: Collapse by resolved IP (`--collapse-by-ip`)  
- Optional: Probe with [httpx](https://github.com/projectdiscovery/httpx) (`--probe`) and save live results  
- Clean output structure:  
  - `merged_subs.txt` → deduplicated hosts  
  - `ip_map.csv` → host-to-IP mappings (if collapse enabled)  
  - `live_hosts.txt` → responsive hosts (if probe enabled)  

---

## 🚀 Installation
Clone the repo and install dependencies:

```bash
git clone https://github.com/logan-sec/dedupe.git
cd dedupe
pip install -r requirements.txt
```
## 🔧 Usage

Run **dedupe** with one or more `.txt` files containing subdomains:

```bash
python3 dedupe.py [options] file1.txt file2.txt ...

```

## 🗺️ Planned Features / Roadmap

Here’s what’s on the horizon for **dedupe**:

- [ ] Add support for reading from directories (auto-merge all `.txt` files in a folder)  
- [ ] Optional JSON output for easier integration with other tools  
- [ ] Parallel DNS/IP resolution for faster collapsing  
- [ ] IPv6 resolution support  
- [ ] Rate-limiting controls to avoid overwhelming DNS resolvers or httpx  
- [ ] More probing options beyond httpx (e.g., curl, custom ports)  
- [ ] Improved error handling and logging  
- [ ] Config file support for common workflows  

✅ Tool already works and saves time today — these updates will make it even better.
