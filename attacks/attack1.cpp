
#include <iostream>
#include <string>
#include <cstring>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <json-c/json.h>

using namespace std;

int connect_server() {
    hostent *host = gethostbyname("as3_server");
    if (!host) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

string read_line(int fd) {
    string line;
    char ch;

    while (recv(fd, &ch, 1, 0) == 1) {
        if (ch == '\n') break;
        line += ch;
    }
    return line;
}

int main() {
    int fd = connect_server();

    if (fd < 0) {
        cerr << "Could not connect to AS3 server\n";
        return 1;
    }

    cout << "Mallory connected to AS3 server\n";

    string request = "{\"type\":\"fetch_bundle\",\"user\":\"bob\"}\n";

    for (int i = 1; i <= 6; i++) {
        if (send(fd, request.c_str(), request.size(), 0) <= 0) {
            cout << "Connection closed\n";
            break;
        }

        string response = read_line(fd);
        if (response.empty()) {
            cout << "No response from server\n";
            break;
        }

        json_object *root = json_tokener_parse(response.c_str());
        if (!root) {
            cout << "Invalid JSON: " << response << endl;
            break;
        }

        json_object *type = nullptr;
        json_object_object_get_ex(root, "type", &type);

        string response_type = type ? json_object_get_string(type) : "";

        if (response_type == "bundle") {
            json_object *bundle = nullptr;
            json_object *opk_id = nullptr;
            json_object *count = nullptr;

            json_object_object_get_ex(root, "bundle", &bundle);
            if (bundle)
                json_object_object_get_ex(bundle, "opk_id", &opk_id);
            json_object_object_get_ex(root, "count", &count);

            cout << "Request " << i
                 << " | OPK ID: "
                 << (opk_id ? json_object_get_int(opk_id) : -1)
                 << " | Remaining: "
                 << (count ? json_object_get_int(count) : -1)
                 << endl;
        } else {
            cout << "Request " << i
                 << " | Server response: " << response << endl;
        }

        json_object_put(root);
    }

    close(fd);
    return 0;
}
