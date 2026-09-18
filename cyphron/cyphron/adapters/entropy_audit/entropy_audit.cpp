// entropy_audit.cpp — pilot polyglot adapter Cyphron (Fullpower B1).
//
// Kontrak adapter: args JSON lewat stdin, hasil JSON di stdout.
//   stdin : {"values": ["<nilai bersesi/cookie/token>", ...]}
//   stdout: {"ok":true,"data":{"results":[{"value_len":..,"entropy":..,
//            "weak":true|false}]},"findings":[...],"requests":0}
//
// Fungsi: hitung Shannon entropy per karakter dari tiap nilai; nilai
// panjang (>=16) dengan entropy rendah (<3.0 bit/char) = kandidat token
// lemah (posture, LEAD — bukan klaim). Murni lokal: TANPA jaringan.
//
// Build (via manifest): g++ -O2 -std=c++17 -o {out} {src}

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Ekstrak daftar string dari field "values" pada JSON flat sederhana.
// Parser JSON minimal: cukup untuk kontrak adapter ini (array of string).
std::vector<std::string> parse_values(const std::string &json) {
  std::vector<std::string> out;
  const std::string key = "\"values\"";
  std::size_t pos = json.find(key);
  if (pos == std::string::npos) return out;
  pos = json.find('[', pos);
  if (pos == std::string::npos) return out;
  ++pos;
  bool in_string = false;
  std::string cur;
  for (; pos < json.size(); ++pos) {
    char c = json[pos];
    if (in_string) {
      if (c == '\\' && pos + 1 < json.size()) {
        char n = json[++pos];
        switch (n) {
          case 'n': cur += '\n'; break;
          case 't': cur += '\t'; break;
          case 'r': cur += '\r'; break;
          default: cur += n;
        }
        continue;
      }
      if (c == '"') { out.push_back(cur); cur.clear(); in_string = false; continue; }
      cur += c;
      continue;
    }
    if (c == '"') { in_string = true; cur.clear(); continue; }
    if (c == ']') break;
  }
  return out;
}

double shannon_entropy(const std::string &s) {
  if (s.empty()) return 0.0;
  std::map<unsigned char, long> freq;
  for (unsigned char c : s) freq[c]++;
  double bits = 0.0;
  const double n = static_cast<double>(s.size());
  for (const auto &kv : freq) {
    const double p = static_cast<double>(kv.second) / n;
    bits -= p * std::log2(p);
  }
  return bits;
}

std::string json_escape(const std::string &s) {
  std::string out;
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c;
    }
  }
  return out;
}

std::string emit_json(double entropy, bool weak, int len,
                      const std::vector<std::string> &weak_values) {
  std::ostringstream o;
  o << "{\"ok\":true,\"data\":{\"results\":[";
  o << "{\"entropy\":" << entropy << ",\"weak\":" << (weak ? "true" : "false")
    << ",\"value_len\":" << len << "}";
  o << "],\"weak_count\":" << weak_values.size() << "}";
  o << ",\"findings\":[";
  for (std::size_t i = 0; i < weak_values.size(); ++i) {
    if (i) o << ",";
    o << "{\"title\":\"Nilai bersesi entropy rendah (" << entropy
      << " bit/karakter)\",\"severity\":\"low\",\"cwe\":\"CWE-330\","
      << "\"description\":\"Nilai sepanjang " << len
      << " karakter memiliki entropy " << entropy
      << " bit/karakter (di bawah ambang 3.0) - pola token lemah/prediktabel. "
      << "Hitung dilakukan lokal oleh engine C++ polyglot; LEAD, bukan klaim.\","
      << "\"recommendation\":\"Gunakan CSPRNG minimal 128-bit entropy untuk "
      << "token bersesi; hindari nilai berpola (timestamp/urut).\","
      << "\"confidence\":0.7,\"finding_class\":\"posture\"}";
  }
  o << "],\"requests\":0}";
  return o.str();
}

}  // namespace

int main() {
  std::string input;
  std::getline(std::cin, input);
  const std::vector<std::string> values = parse_values(input);

  std::vector<std::string> weak_values;
  std::string last_entropy = "0";
  std::string last_len = "0";
  bool weak_any = false;
  double last = 0.0;
  int lastn = 0;

  for (const std::string &v : values) {
    const double e = shannon_entropy(v);
    const bool weak = v.size() >= 16 && e < 3.0;
    last = e;
    lastn = static_cast<int>(v.size());
    if (weak) {
      weak_any = true;
      weak_values.push_back(v);
    }
  }
  std::ostringstream e; e << last;
  std::ostringstream l; l << lastn;
  std::cout << emit_json(last, weak_any && !values.empty(), lastn,
                         weak_values)
            << std::endl;
  return 0;
}
