#include "network.h"
#include <curl/curl.h>
//#include <libcurl>
#include <iostream>

// Callback для записи данных
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    output->append(static_cast<char*>(contents), total_size);
    return total_size;
}

// 🚨 УЯЗВИМОСТЬ 5: Нет проверки URL, нет таймаутов, нет проверки сертификатов
std::string downloadFile(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string response;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (curl) {
        // 🔴 УЯЗВИМОСТЬ: Нет проверки, что URL не содержит инъекций
        // 🔴 УЯЗВИМОСТЬ: Нет таймаута — может висеть бесконечно
        // 🔴 УЯЗВИМОСТЬ: Нет проверки SSL сертификата (CURLOPT_SSL_VERIFYPEER = 0)
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);  // 🔴 УЯЗВИМОСТЬ: Не проверяем SSL
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);        // 🔴 УЯЗВИМОСТЬ: Нет таймаута
        
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl error: " << curl_easy_strerror(res) << std::endl;
        }
        
        curl_easy_cleanup(curl);
    }
    
    curl_global_cleanup();
    return response;
}