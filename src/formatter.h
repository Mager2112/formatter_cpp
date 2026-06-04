#ifndef FORMATTER_H
#define FORMATTER_H

#include <string>
#include <vector>

struct User {
    std::string name;
    std::string age;
    std::string address;
    std::string date;
};

std::string detectEncoding(const std::string& filename);
std::vector<User> readData(const std::string& filename);
std::string fixDate(const std::string& date_str);
std::string shortenName(const std::string& name, int level);
std::string shortenDate(const std::string& date_str, int level);
std::string shortenAddress(const std::string& address, int level, int max_len);
void printTable(const std::vector<User>& data);
int getTerminalWidth();

#endif