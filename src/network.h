#ifndef NETWORK_H
#define NETWORK_H

#include <string>

// 🚨 УЯЗВИМОСТЬ 5: Нет проверки на большие файлы, нет таймаутов
std::string downloadFile(const std::string& url);

#endif