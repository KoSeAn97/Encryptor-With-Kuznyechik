#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <fstream>

#include <string>
using std::string;
using std::getline;

#include <vector>
using std::vector;

#include <limits>
using std::numeric_limits;

#include <stdexcept>

#include "Kuznyechik.hpp"
#include "mycrypto.hpp"

void print_help(const char * argv0) {
	const char * usage =
R"(where ACTION is:
--e
 for encrypt the message
--d
 for decrypt the message

file format:
KEY=<key-string>            : 32-length hex string
IV=<iv-string>              : 32-length hex string
INPUT=<plaintext-string>    : any hex string you like

output file = ./kuznyechik_cfb_output.txt
)";
	cout << "Usage " << argv0 << " --path=<path_to_file> ACTION" << endl;
	cout << usage;
}

void check_argc(int argc, int from, int to=numeric_limits<int>::max()) {
	if(argc < from)
		throw std::invalid_argument(
			"too few arguments for operation"
		);
	if(argc > to)
		throw std::invalid_argument(
			"too many arguments for operation"
		);
}

vector<string> split(const string & s, char ch) {
    vector<string> v;

    string::size_type i = 0;
    string::size_type j = s.find(ch);
    while(j != string::npos) {
        v.push_back(s.substr(i, j-i));
        i = ++j;
        j = s.find(ch, j);

        if(j == string::npos)
            v.push_back(s.substr(i, s.size()-i));
    }
    return v;
}

vector<string> read_cipher_params(const string & filename) {
	std::ifstream fin(filename);
	vector<string> result, params {"KEY", "IV", "INPUT"};
	for(auto & p : params) {
		string tmp;
		getline(fin, tmp);
		auto line = split(tmp, '=');
		if(line.size() != 2 || line[0] != p)
			throw std::invalid_argument("Bad file");
		result.push_back(line[1]);
	}
	return result;
}

int main(int argc, char ** argv) {
	try {
		check_argc(argc, 2);
		if(string(argv[1]) == "--help") {
			print_help(argv[0]);
			return 0;
		}
		check_argc(argc, 3, 3);
		string filename(argv[1]);
		string action(argv[2]);

		auto path_params = split(filename, '=');
		if(path_params.size() != 2 || path_params[0] != "--path")
			throw std::invalid_argument(
				string("Error in terminal parameters: ") + filename
			);
		filename = path_params[1];

		bool is_enc;
		if(action == "--e") {
			is_enc = true;
		} else if(action == "--d") {
			is_enc = false;
		} else {
			throw std::invalid_argument(
				string("Unknown action: ") + action
			);
		}

		auto cipher_params = read_cipher_params(filename);
		ByteBlock key = hex_to_bytes(cipher_params[0]);
		ByteBlock iv = hex_to_bytes(cipher_params[1]);
		ByteBlock message = hex_to_bytes(cipher_params[2]);
		ByteBlock output;

		CFB_Mode<Kuznyechik> encryptor(Kuznyechik(key), iv);

		if(is_enc) {
			encryptor.encrypt(message, output);
		} else {
			encryptor.decrypt(message, output);
		}

		std::ofstream fout("kuznyechik_cfb_output.txt");
		fout << "KEY=" << cipher_params[0] << endl;
		fout << "IV=" << cipher_params[1] << endl;
		fout << "INPUT=" << cipher_params[2] << endl;
		fout << "OUTPUT=" << hex_representation(output) << endl;
		fout.close();
	} catch(const std::exception & e) {
		cerr << "Error: " << e.what() << endl;
		cerr << "For help type: " << endl << argv[0] << " --help" << endl;
		return 1;
	}

	return 0;
}
