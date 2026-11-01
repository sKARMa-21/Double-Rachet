
#include <iostream>
#include <string>
#include <thread>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <json-c/json.h>

using namespace std;

int gap = 10;
bool attacked = false;

int connect_server() {
    hostent *host = gethostbyname("as3_server");
    if (!host) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

string modify(string line) {
    if (line.find("\"ct\"") != string::npos)
        cout << "Encrypted message received: " << line << endl;
        
    if (attacked) return line;

    json_object *root = json_tokener_parse(line.c_str());
    if (!root) return line;

    json_object *type, *frames;

    if (json_object_object_get_ex(root, "type", &type) &&
        json_object_get_type(type) == json_type_string &&
        string(json_object_get_string(type)) == "frames" &&
        json_object_object_get_ex(root, "frames", &frames) &&
        json_object_get_type(frames) == json_type_array) {

        int count = json_object_array_length(frames);

        for (int i = 0; i < count; i++) {
            json_object *frame = json_object_array_get_idx(frames, i);
            json_object *from, *to, *header, *n;

            if (!json_object_object_get_ex(frame, "from", &from) ||
                !json_object_object_get_ex(frame, "to", &to) ||
                !json_object_object_get_ex(frame, "header", &header) ||
                !json_object_object_get_ex(header, "n", &n))
                continue;

            if (string(json_object_get_string(from)) == "alice" &&
                string(json_object_get_string(to)) == "bob") {

                int old_n = json_object_get_int(n);
                int new_n = old_n + gap;

                json_object_object_add(header, "n",
                                       json_object_new_int(new_n));

                line = json_object_to_json_string_ext(
                    root, JSON_C_TO_STRING_PLAIN);

                cout << "Changed n: " << old_n
                     << " -> " << new_n << endl;

                attacked = true;
                break;
            }
        }
    }

    json_object_put(root);
    return line;
}

void relay(int src, int dst, bool change) {
    char buf[4096];
    string pending;

    while (true) {
        int n = recv(src, buf, sizeof(buf), 0);
        if (n <= 0) break;

        pending.append(buf, n);

        size_t pos;
        while ((pos = pending.find('\n')) != string::npos) {
            string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);

            if (change)
                line = modify(line);

            line += "\n";

            size_t sent = 0;
            while (sent < line.size()) {
                ssize_t k = send(dst, line.data() + sent,
                                 line.size() - sent, MSG_NOSIGNAL);
                if (k <= 0) return;
                sent += k;
            }
        }
    }

    shutdown(dst, SHUT_WR);
}

void handle_client(int bob) {
    cout << "Bob connected to Mallory" << endl;
    int server = connect_server();
    if (server < 0) {
        close(bob);
        return;
    }

    thread t1(relay, bob, server, false);
    thread t2(relay, server, bob, true);

    t1.join();
    t2.join();

    close(server);
    close(bob);
}

int main() {
    if (getenv("COUNTER_GAP"))
        gap = atoi(getenv("COUNTER_GAP"));

    int listener = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
               &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9001);

    if (bind(listener, (sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listener, 10) < 0) {
        perror("listen");
        return 1;
    }

    cout << "Mallory listening on port 9001" << endl;
    cout << "Counter gap: " << gap << endl;

    while (true) {
        int bob = accept(listener, nullptr, nullptr);
        if (bob < 0) continue;

        thread(handle_client, bob).detach();
    }
}
