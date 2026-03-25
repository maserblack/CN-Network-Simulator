/*
 * ============================================================
 *  ITL351 – Computer Networks Lab  |  Semester Project
 *  Network Protocol Stack Simulator
 *  Language : C++17  (compile with: g++ -std=c++17 -o sim network_simulator.cpp)
 * ============================================================
 *
 *  PHYSICAL  LAYER  : End-Devices, Hubs, Connections, Topology
 *  DATA-LINK LAYER  : Bridge, Switch (MAC learning), CRC error
 *                     control, CSMA/CD access control,
 *                     Go-Back-N sliding-window flow control
 * ============================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <bitset>
#include <cstdint>
#include <functional>
#include <random>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <termios.h>
#include <unistd.h>
#include <memory>
#include <set>
#include <limits>

using namespace std;

// ─────────────────────────────────────────────
//  Utility helpers
// ─────────────────────────────────────────────
static void separator(char c = '=', int n = 60) {
    cout << string(n, c) << "\n";
}
static void heading(const string& s) {
    separator();
    cout << "  " << s << "\n";
    separator();
}

// ─────────────────────────────────────────────
//  CRC-16 (CCITT) for error detection
// ─────────────────────────────────────────────
uint16_t crc16(const string& data) {
    uint16_t crc = 0xFFFF;
    for (unsigned char byte : data) {
        crc ^= (uint16_t)byte << 8;
        for (int i = 0; i < 8; i++) {
            if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
            else              crc <<= 1;
        }
    }
    return crc;
}

// ─────────────────────────────────────────────
//  Frame  (Data-Link PDU)
// ─────────────────────────────────────────────
struct Frame {
    string src_mac;
    string dst_mac;
    string payload;
    uint16_t checksum;
    int seq_num   = 0;   
    bool is_ack   = false;
    int  ack_num  = -1;
    bool corrupted = false;

    Frame() {}
    Frame(const string& src, const string& dst, const string& data, int seq = 0)
        : src_mac(src), dst_mac(dst), payload(data),
          checksum(crc16(data)), seq_num(seq) {}

    bool verify() const { return crc16(payload) == checksum; }

    string to_string() const {
        ostringstream os;
        os << "[Frame seq=" << seq_num
           << " src=" << src_mac << " dst=" << dst_mac
           << " data=\"" << payload << "\""
           << " CRC=0x" << hex << uppercase << checksum << dec << "]";
        return os.str();
    }
};

// ─────────────────────────────────────────────
//  Forward declarations
// ─────────────────────────────────────────────
class NetworkDevice;
class EndDevice;
class Hub;
class Bridge;
class Switch;

// ─────────────────────────────────────────────
//  Connection  (simulated physical link)
// ─────────────────────────────────────────────
struct Connection {
    string device_a;
    string device_b;
    bool   busy = false;   // used for CSMA/CD

    Connection(const string& a, const string& b) : device_a(a), device_b(b) {}

    bool connects(const string& d) const {
        return device_a == d || device_b == d;
    }
    string other(const string& d) const {
        return device_a == d ? device_b : device_a;
    }
};

// ─────────────────────────────────────────────
//  Network (global topology)
// ─────────────────────────────────────────────
class Network {
public:
    map<string, shared_ptr<NetworkDevice>> devices;
    vector<Connection> connections;

    bool addDevice(shared_ptr<NetworkDevice> dev);
    bool connect(const string& a, const string& b);
    bool isConnected(const string& a, const string& b) const;
    vector<string> neighbors(const string& name) const;
    void printTopology() const;
    int  broadcastDomains() const;
    int  collisionDomains() const;

    // CSMA/CD channel state per connection
    bool isChannelBusy(const string& a, const string& b) const;
    void setChannelBusy(const string& a, const string& b, bool busy);
};

// ─────────────────────────────────────────────
//  Base NetworkDevice
// ─────────────────────────────────────────────
class NetworkDevice {
public:
    string name;
    string type;   // "EndDevice" | "Hub" | "Bridge" | "Switch"

    explicit NetworkDevice(const string& n, const string& t)
        : name(n), type(t) {}
    virtual ~NetworkDevice() = default;

    virtual void receiveFrame(const Frame& f, const string& from_port,
                              Network& net) = 0;
};

// ─────────────────────────────────────────────
//  End Device
// ─────────────────────────────────────────────
class EndDevice : public NetworkDevice {
public:
    string mac;
    vector<Frame> inbox;

    EndDevice(const string& n, const string& mac_addr)
        : NetworkDevice(n, "EndDevice"), mac(mac_addr) {}

    void receiveFrame(const Frame& f, const string& /*from*/,
                      Network& /*net*/) override {
        if (!f.verify()) {
            cout << "  [" << name << "] ERROR: Frame seq=" << f.seq_num
                 << " from " << f.src_mac << " – CRC mismatch! Frame dropped.\n";
            return;
        }
        if (f.dst_mac == mac || f.dst_mac == "FF:FF:FF:FF:FF:FF") {
            cout << "  [" << name << "] Received: \"" << f.payload
                 << "\" from " << f.src_mac << " (seq=" << f.seq_num << ")\n";
            inbox.push_back(f);
        } else {
            cout << "  [" << name << "] Ignored frame destined for " << f.dst_mac << "\n";
        }
    }

    // Physical layer send – no MAC logic, raw bit delivery
    void sendRaw(const string& data, const string& dst_name,
                 Network& net);

    // Data-link layer send with CRC + CSMA/CD + Go-Back-N
    void sendFrames(const vector<string>& messages, const string& dst_mac,
                    const string& dst_name, Network& net,
                    int window_size = 4);
};

// ─────────────────────────────────────────────
//  Hub  (Physical-layer multiport repeater)
// ─────────────────────────────────────────────
class Hub : public NetworkDevice {
public:
    int port_count;

    Hub(const string& n, int ports)
        : NetworkDevice(n, "Hub"), port_count(ports) {}

    void receiveFrame(const Frame& f, const string& from_port,
                      Network& net) override;
};

// ─────────────────────────────────────────────
//  Bridge  (Data-link device, 2 ports)
// ─────────────────────────────────────────────
class Bridge : public NetworkDevice {
public:
    map<string, string> mac_table; // mac -> port (neighbor name)

    Bridge(const string& n) : NetworkDevice(n, "Bridge") {}

    void receiveFrame(const Frame& f, const string& from_port,
                      Network& net) override;

    void printMACTable() const {
        cout << "  Bridge [" << name << "] MAC Table:\n";
        if (mac_table.empty()) { cout << "    (empty)\n"; return; }
        for (auto& [mac, port] : mac_table)
            cout << "    " << mac << " -> port " << port << "\n";
    }
};

// ─────────────────────────────────────────────
//  Switch  (Data-link device, multi-port)
// ─────────────────────────────────────────────
class Switch : public NetworkDevice {
public:
    map<string, string> mac_table; // mac -> neighbor-device name

    Switch(const string& n) : NetworkDevice(n, "Switch") {}

    void receiveFrame(const Frame& f, const string& from_port,
                      Network& net) override;

    void printMACTable() const {
        cout << "  Switch [" << name << "] MAC Table:\n";
        if (mac_table.empty()) { cout << "    (empty)\n"; return; }
        for (auto& [mac, port] : mac_table)
            cout << "    " << mac << " -> port " << port << "\n";
    }
};

// ─────────────────────────────────────────────
//  Network – method implementations
// ─────────────────────────────────────────────
bool Network::addDevice(shared_ptr<NetworkDevice> dev) {
    if (devices.count(dev->name)) {
        cout << "  Device '" << dev->name << "' already exists!\n";
        return false;
    }
    devices[dev->name] = dev;
    cout << "  [+] " << dev->type << " '" << dev->name << "' created.\n";
    return true;
}

bool Network::connect(const string& a, const string& b) {
    if (!devices.count(a) || !devices.count(b)) {
        cout << "  ERROR: one or both devices not found.\n";
        return false;
    }
    if (isConnected(a, b)) {
        cout << "  Already connected.\n";
        return false;
    }
    connections.push_back(Connection(a, b));
    cout << "  [~] " << a << " <---> " << b << "\n";
    return true;
}

bool Network::isConnected(const string& a, const string& b) const {
    for (auto& c : connections)
        if ((c.device_a == a && c.device_b == b) ||
            (c.device_a == b && c.device_b == a)) return true;
    return false;
}

vector<string> Network::neighbors(const string& name) const {
    vector<string> res;
    for (auto& c : connections)
        if (c.connects(name)) res.push_back(c.other(name));
    return res;
}

void Network::printTopology() const {
    heading("Network Topology");
    cout << "  Devices (" << devices.size() << "):\n";
    for (auto& [n, d] : devices)
        cout << "    [" << d->type << "] " << n << "\n";
    cout << "\n  Links (" << connections.size() << "):\n";
    for (auto& c : connections)
        cout << "    " << c.device_a << " <---> " << c.device_b << "\n";
    separator('-');
    cout << "  Broadcast Domains : " << broadcastDomains() << "\n";
    cout << "  Collision Domains : " << collisionDomains() << "\n";
    separator();
}

bool Network::isChannelBusy(const string& a, const string& b) const {
    for (const auto& c : connections)
        if ((c.device_a == a && c.device_b == b) ||
            (c.device_a == b && c.device_b == a))
            return c.busy;
    return false;
}

void Network::setChannelBusy(const string& a, const string& b, bool busy) {
    for (auto& c : connections)
        if ((c.device_a == a && c.device_b == b) ||
            (c.device_a == b && c.device_b == a))
            c.busy = busy;
}


int Network::broadcastDomains() const {
    
    map<string, string> parent;
    function<string(const string&)> find = [&](const string& x) -> string {
        return parent[x] == x ? x : parent[x] = find(parent[x]);
    };
    for (auto& [n, _] : devices) parent[n] = n;

    
    for (auto& [n, d] : devices) {
        if (d->type == "Hub") {
            auto nbrs = neighbors(n);
            for (size_t i = 1; i < nbrs.size(); i++) {
                
                string ra = find(nbrs[0]), rb = find(nbrs[i]);
                if (ra != rb) parent[rb] = ra;
            }
            
            if (!nbrs.empty()) {
                parent[find(n)] = find(nbrs[0]);
            }
        }
    }

   
    set<string> domains;
    for (auto& [n, d] : devices) {
        if (d->type != "Switch" && d->type != "Bridge") {
            domains.insert(find(n));
        }
    }
    
    for (auto& [n, d] : devices) {
        if (d->type == "Switch" || d->type == "Bridge") {
            auto nbrs = neighbors(n);
            for (auto& nb : nbrs) domains.insert(find(nb));
        }
    }
    return max(1, (int)domains.size());
}

int Network::collisionDomains() const {
   
    int cd = 0;
    set<pair<string,string>> counted;

    for (auto& c : connections) {
        auto da = devices.at(c.device_a);
        auto db = devices.at(c.device_b);
        bool aIsHub = da->type == "Hub";
        bool bIsHub = db->type == "Hub";

        if (!aIsHub && !bIsHub) {
            
            cd++;
        }
        
    }

    
    for (auto& [n, d] : devices)
        if (d->type == "Hub") cd++;

    return max(1, cd);
}

// ─────────────────────────────────────────────
//  Hub – flood to all ports except origin
// ─────────────────────────────────────────────
void Hub::receiveFrame(const Frame& f, const string& from_port,
                       Network& net) {
    cout << "  [HUB " << name << "] Flooding frame from " << from_port << "\n";
    for (auto& nbr : net.neighbors(name)) {
        if (nbr == from_port) continue;
        if (net.devices.count(nbr))
            net.devices[nbr]->receiveFrame(f, name, net);
    }
}

// ─────────────────────────────────────────────
//  Bridge – selective forwarding
// ─────────────────────────────────────────────
void Bridge::receiveFrame(const Frame& f, const string& from_port,
                           Network& net) {
    // Learn source
    mac_table[f.src_mac] = from_port;
    cout << "  [BRIDGE " << name << "] Learned " << f.src_mac
         << " on port " << from_port << "\n";

    if (f.dst_mac == "FF:FF:FF:FF:FF:FF") {
        // Flood
        for (auto& nbr : net.neighbors(name)) {
            if (nbr == from_port) continue;
            net.devices[nbr]->receiveFrame(f, name, net);
        }
        return;
    }

    if (mac_table.count(f.dst_mac)) {
        string out_port = mac_table[f.dst_mac];
        if (out_port == from_port) {
            cout << "  [BRIDGE " << name << "] Filtered (same segment)\n";
            return;
        }
        cout << "  [BRIDGE " << name << "] Forwarding to port " << out_port << "\n";
        net.devices[out_port]->receiveFrame(f, name, net);
    } else {
        cout << "  [BRIDGE " << name << "] Unknown dst – flooding\n";
        for (auto& nbr : net.neighbors(name)) {
            if (nbr == from_port) continue;
            net.devices[nbr]->receiveFrame(f, name, net);
        }
    }
}

// ─────────────────────────────────────────────
//  Switch – selective forwarding with learning
// ─────────────────────────────────────────────
void Switch::receiveFrame(const Frame& f, const string& from_port,
                           Network& net) {
    // Address learning
    mac_table[f.src_mac] = from_port;
    cout << "  [SWITCH " << name << "] Learned " << f.src_mac
         << " on port " << from_port << "\n";

    if (f.dst_mac == "FF:FF:FF:FF:FF:FF") {
        cout << "  [SWITCH " << name << "] Broadcast – flooding all ports\n";
        for (auto& nbr : net.neighbors(name)) {
            if (nbr == from_port) continue;
            net.devices[nbr]->receiveFrame(f, name, net);
        }
        return;
    }

    if (mac_table.count(f.dst_mac)) {
        string out_port = mac_table[f.dst_mac];
        if (out_port == from_port) { return; }
        cout << "  [SWITCH " << name << "] Forwarding " << f.dst_mac
             << " -> port " << out_port << "\n";
        net.devices[out_port]->receiveFrame(f, name, net);
    } else {
        cout << "  [SWITCH " << name << "] Unknown MAC – flooding\n";
        for (auto& nbr : net.neighbors(name)) {
            if (nbr == from_port) continue;
            net.devices[nbr]->receiveFrame(f, name, net);
        }
    }
}

// ─────────────────────────────────────────────
//  EndDevice – raw physical send
// ─────────────────────────────────────────────
void EndDevice::sendRaw(const string& data, const string& dst_name,
                        Network& net) {
    auto nbrs = net.neighbors(name);
    if (nbrs.empty()) {
        cout << "  [" << name << "] Not connected to any device!\n";
        return;
    }
    // Represent as bits (ASCII → binary string for display)
    string bits;
    for (char ch : data)
        bits += bitset<8>(ch).to_string() + " ";

    cout << "\n  [" << name << "] >> Raw transmission to " << dst_name << "\n";
    cout << "  Data   : \"" << data << "\"\n";
    cout << "  Bits   : " << bits << "\n";

    // Pass to the first (only) neighbor
    Frame f(mac, "FF:FF:FF:FF:FF:FF", data);
    for (auto& nbr : nbrs) {
        if (net.devices.count(nbr))
            net.devices[nbr]->receiveFrame(f, name, net);
    }
}

// ─────────────────────────────────────────────
//  CSMA/CD – attempt to acquire channel
// ─────────────────────────────────────────────
static bool csmacd_send(const string& sender, const string& neighbor,
                        Network& net, int attempt = 1) {
    if (attempt > 5) {
        cout << "  [CSMA/CD] Max retries reached for " << sender << ". Aborting.\n";
        return false;
    }
    if (net.isChannelBusy(sender, neighbor)) {
        cout << "  [CSMA/CD] Channel BUSY – " << sender
             << " waits (attempt " << attempt << ")\n";
        // Exponential backoff simulation
        cout << "  [CSMA/CD] Backoff slot = " << attempt << " unit(s)\n";
        return csmacd_send(sender, neighbor, net, attempt + 1);
    }
    net.setChannelBusy(sender, neighbor, true);
    cout << "  [CSMA/CD] Channel IDLE – " << sender << " begins transmission.\n";
    return true;
}

// ─────────────────────────────────────────────
//  EndDevice – DLL send with CRC + CSMA/CD + Go-Back-N
// ─────────────────────────────────────────────
void EndDevice::sendFrames(const vector<string>& messages,
                            const string& dst_mac,
                            const string& dst_name,
                            Network& net,
                            int window_size) {
    auto nbrs = net.neighbors(name);
    if (nbrs.empty()) {
        cout << "  [" << name << "] Not connected!\n"; return;
    }
    string next_hop = nbrs[0]; 

    heading("Data-Link Transmission: " + name + " --> " + dst_name);
    cout << "  Window Size (Go-Back-N) : " << window_size << "\n";
    cout << "  Error Control           : CRC-16\n";
    cout << "  Access Control          : CSMA/CD\n\n";

    int total   = (int)messages.size();
    int base    = 0;       
    int next_seq = 0;

    
    vector<bool> acked(total, false);

    while (base < total) {
       
        while (next_seq < base + window_size && next_seq < total) {
            Frame f(mac, dst_mac, messages[next_seq], next_seq);

            
            separator('-');
            cout << "  Sending " << f.to_string() << "\n";
            if (!csmacd_send(name, next_hop, net)) return;

            
            net.devices[next_hop]->receiveFrame(f, name, net);
            net.setChannelBusy(name, next_hop, false);

            next_seq++;
        }

        
        for (int i = base; i < next_seq; i++) {
            if (!acked[i]) {
                cout << "\n  [ACK] Receiver ACKs frame seq=" << i << "\n";
                acked[i] = true;
            }
        }

       
        while (base < total && acked[base]) base++;

        
        if (base < total && next_seq == base + window_size) {
            
            cout << "  [Go-Back-N] Window full, waiting for ACK...\n";
        }
    }

    separator('=');
    cout << "  All " << total << " frame(s) successfully delivered.\n";
    separator();
}

// ─────────────────────────────────────────────
//  Helper: cast device to EndDevice
// ─────────────────────────────────────────────
static EndDevice* asED(Network& net, const string& name) {
    auto it = net.devices.find(name);
    if (it == net.devices.end()) return nullptr;
    return dynamic_cast<EndDevice*>(it->second.get());
}
static Switch* asSW(Network& net, const string& name) {
    auto it = net.devices.find(name);
    if (it == net.devices.end()) return nullptr;
    return dynamic_cast<Switch*>(it->second.get());
}

// ─────────────────────────────────────────────
//  TEST-CASE RUNNERS
// ─────────────────────────────────────────────

/* TC-1 : Two end devices, direct link, physical-layer send */
void tc1_direct_link() {
    heading("TEST CASE 1: Two End Devices – Direct Link (Physical Layer)");
    Network net;
    net.addDevice(make_shared<EndDevice>("DevA", "AA:AA:AA:AA:AA:01"));
    net.addDevice(make_shared<EndDevice>("DevB", "AA:AA:AA:AA:AA:02"));
    net.connect("DevA", "DevB");
    net.printTopology();

    auto* a = asED(net, "DevA");
    auto* b = asED(net, "DevB");

    cout << "\n--- DevA sends raw data to DevB ---\n";
    a->sendRaw("Hello DevB!", "DevB", net);

    cout << "\n--- DevB sends raw data to DevA ---\n";
    b->sendRaw("Hi back DevA!", "DevA", net);
}

/* TC-2 : Star topology – 5 end devices + hub */
void tc2_hub_star() {
    heading("TEST CASE 2: Star Topology – 5 End Devices + Hub (Physical Layer)");
    Network net;

    auto hub = make_shared<Hub>("Hub1", 5);
    net.addDevice(hub);

    for (int i = 1; i <= 5; i++) {
        string dname = "PC" + to_string(i);
        string mac   = "BB:BB:BB:BB:BB:0" + to_string(i);
        net.addDevice(make_shared<EndDevice>(dname, mac));
        net.connect(dname, "Hub1");
    }
    net.printTopology();

    cout << "\n--- PC1 broadcasts a message (hub floods to all) ---\n";
    auto* pc1 = asED(net, "PC1");
    pc1->sendRaw("Hello everyone!", "Hub1", net);
}

/* TC-3 : Switch + 5 end devices – DLL protocols */
void tc3_switch_five_devices() {
    heading("TEST CASE 3: Switch with 5 End Devices – DLL Protocols");
    Network net;

    auto sw = make_shared<Switch>("SW1");
    net.addDevice(sw);

    vector<string> names, macs;
    for (int i = 1; i <= 5; i++) {
        string dname = "Host" + to_string(i);
        string mac   = "CC:CC:CC:CC:CC:0" + to_string(i);
        names.push_back(dname);
        macs.push_back(mac);
        net.addDevice(make_shared<EndDevice>(dname, mac));
        net.connect(dname, "SW1");
    }
    net.printTopology();

    // Host1 sends multiple frames to Host5
    auto* h1 = asED(net, "Host1");
    string dst_mac = macs[4]; // Host5 mac
    vector<string> msgs = {"Frame-0", "Frame-1", "Frame-2", "Frame-3",
                            "Frame-4", "Frame-5"};

    h1->sendFrames(msgs, dst_mac, "Host5", net, /*window=*/4);

    cout << "\n";
    sw->printMACTable();

    cout << "\n--- Host3 sends to Host2 (after learning) ---\n";
    auto* h3 = asED(net, "Host3");
    h3->sendFrames({"Hi Host2!"}, macs[1], "Host2", net, 1);
    sw->printMACTable();
}

/* TC-4 : Two hub-stars connected via a switch – 10 devices */
void tc4_two_stars_switch() {
    heading("TEST CASE 4: Two Hub-Stars (5+5) Connected via Switch");
    Network net;

    // Hub A side
    net.addDevice(make_shared<Hub>("HubA", 5));
    for (int i = 1; i <= 5; i++) {
        string d = "A" + to_string(i);
        string m = "DA:DA:DA:DA:DA:0" + to_string(i);
        net.addDevice(make_shared<EndDevice>(d, m));
        net.connect(d, "HubA");
    }

    // Hub B side
    net.addDevice(make_shared<Hub>("HubB", 5));
    for (int i = 1; i <= 5; i++) {
        string d = "B" + to_string(i);
        string m = "DB:DB:DB:DB:DB:0" + to_string(i);
        net.addDevice(make_shared<EndDevice>(d, m));
        net.connect(d, "HubB");
    }

    // Switch connecting the two hubs
    auto sw = make_shared<Switch>("SW_Core");
    net.addDevice(sw);
    net.connect("HubA", "SW_Core");
    net.connect("HubB", "SW_Core");

    net.printTopology();

    // A1 sends to B3
    auto* a1 = asED(net, "A1");
    string b3_mac = "DB:DB:DB:DB:DB:03";
    vector<string> data = {"Ping from A1", "Ping2", "Ping3"};
    a1->sendFrames(data, b3_mac, "B3", net, 3);

    cout << "\n";
    sw->printMACTable();
}

/* TC-5 : CRC Error Detection Demo */
void tc5_crc_demo() {
    heading("TEST CASE 5: CRC Error Detection Demo");

    string msg = "NetworkData";
    uint16_t crc = crc16(msg);
    cout << "  Original data   : \"" << msg << "\"\n";
    cout << "  CRC-16 checksum : 0x" << hex << uppercase << crc << dec << "\n\n";

    Frame good("AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02", msg);
    Frame bad = good;
    bad.payload[0] = 'X';  // corrupt payload without updating CRC

    cout << "  Good frame verify : " << (good.verify() ? "PASS ✓" : "FAIL ✗") << "\n";
    cout << "  Bad  frame verify : " << (bad.verify()  ? "PASS ✓" : "FAIL ✗") << "\n\n";

    // Deliver corrupt frame to an end device
    Network net;
    auto dev = make_shared<EndDevice>("RX", "AA:AA:AA:AA:AA:02");
    net.addDevice(dev);
    net.addDevice(make_shared<EndDevice>("TX", "AA:AA:AA:AA:AA:01"));
    net.connect("TX", "RX");

    cout << "  -- Sending GOOD frame --\n";
    net.devices["RX"]->receiveFrame(good, "TX", net);
    cout << "\n  -- Sending CORRUPTED frame --\n";
    net.devices["RX"]->receiveFrame(bad, "TX", net);
}

/* TC-6 : Go-Back-N with simulated loss */
void tc6_gobackn_demo() {
    heading("TEST CASE 6: Go-Back-N Sliding Window Demo");
    Network net;

    net.addDevice(make_shared<EndDevice>("Sender", "EE:EE:EE:EE:EE:01"));
    net.addDevice(make_shared<EndDevice>("Receiver", "EE:EE:EE:EE:EE:02"));
    net.connect("Sender", "Receiver");

    auto* s = asED(net, "Sender");
    vector<string> msgs;
    for (int i = 0; i < 8; i++)
        msgs.push_back("Packet-" + to_string(i));

    s->sendFrames(msgs, "EE:EE:EE:EE:EE:02", "Receiver", net, /*window=*/3);
}

// ─────────────────────────────────────────────
//  INTERACTIVE MENU
// ─────────────────────────────────────────────
void printMenu() {
    separator();
    cout << "  ITL351 – Network Simulator  |  Main Menu\n";
    separator();
    cout << "  [1] TC-1 : Direct link – two end devices (Physical Layer)\n";
    cout << "  [2] TC-2 : Star topology – 5 devices + hub (Physical Layer)\n";
    cout << "  [3] TC-3 : Switch + 5 devices – CRC, CSMA/CD, Go-Back-N\n";
    cout << "  [4] TC-4 : Two hub-stars connected by switch (10 devices)\n";
    cout << "  [5] TC-5 : CRC error detection demo\n";
    cout << "  [6] TC-6 : Go-Back-N sliding window demo\n";
    cout << "  [0] Exit\n";
    separator();
    cout << "  Choice: ";
}

int main() {
    cout << "\n";
    heading("ITL351 Computer Networks Lab – Semester Project");
    cout << "  Protocol Stack Simulator (Physical + Data-Link Layers)\n";
    separator();

    // Fix terminal line discipline for VS Code integrated terminal on Mac
    struct termios oldt, newt;
    if (isatty(STDIN_FILENO)) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag |= (ICANON | ECHO);   // ensure canonical mode + echo are ON
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    int choice = -1;
    char buf[64];
    while (choice != 0) {
        printMenu();
        fflush(stdout);
        memset(buf, 0, sizeof(buf));
        if (!fgets(buf, sizeof(buf), stdin)) break;
        // parse first digit found
        choice = -1;
        for (int i = 0; buf[i]; i++) {
            if (buf[i] >= '0' && buf[i] <= '9') {
                choice = buf[i] - '0';
                break;
            }
        }
        if (choice == -1) { cout << "  Invalid choice.\n\n"; continue; }
        cout << "\n";
        switch (choice) {
            case 1: tc1_direct_link();           break;
            case 2: tc2_hub_star();              break;
            case 3: tc3_switch_five_devices();   break;
            case 4: tc4_two_stars_switch();      break;
            case 5: tc5_crc_demo();              break;
            case 6: tc6_gobackn_demo();          break;
            case 0: cout << "  Goodbye!\n"; break;
            default: cout << "  Invalid choice.\n"; break;
        }
        cout << "\n";
    }

    
    if (isatty(STDIN_FILENO))
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return 0;
}
