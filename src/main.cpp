#include "formatter.h"
#include "network.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <unistd.h>

int main(int argc, char* argv[]) {
    std::string input_path;
    bool from_url = false;
    
    // Простейший парсинг аргументов (без getopt_long для уязвимости)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--input") {
            if (i + 1 < argc) {
                input_path = argv[++i];
                if (input_path.find("http://") == 0 || input_path.find("https://") == 0) {
                    from_url = true;
                }
            }
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Formatter C++ - Table formatter\n";
            std::cout << "Usage: " << argv[0] << " -i <file_or_url>\n";
            return 0;
        }
    }
    
    if (input_path.empty()) {
        std::cerr << "Error: No input file specified. Use -i <file_or_url>" << std::endl;
        return 1;
    }
    
    std::vector<User> data;
    
    if (from_url) {
        std::cout << "Downloading from " << input_path << "..." << std::endl;
        // 🚨 УЯЗВИМОСТЬ: downloadFile может скачать очень большой файл
        std::string content = downloadFile(input_path);
        
        // Сохраняем во временный файл
        std::string temp_path = "/tmp/formatter_temp_" + std::to_string(getpid());
        std::ofstream temp_file(temp_path);
        if (!temp_file.is_open()) {
            std::cerr << "Error: Cannot create temp file" << std::endl;
            return 1;
        }
        temp_file << content;
        temp_file.close();
        
        data = readData(temp_path);
        
        // Удаляем временный файл
        std::remove(temp_path.c_str());
    } else {
        data = readData(input_path);
    }
    
    printTable(data);
    
    return 0;
}