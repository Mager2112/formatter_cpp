#include "formatter.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <sys/ioctl.h>
#include <unistd.h>
#include <regex>
#include <chrono>
#include <ctime>
#include <iomanip>

// 🚨 УЯЗВИМОСТЬ 1: Нет проверки на переполнение буфера при работе с путями
int getTerminalWidth() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col > 0 ? w.ws_col : 80;
}

// 🚨 УЯЗВИМОСТЬ 2: Простая "детекция" кодировки (ненадежна)
std::string detectEncoding(const std::string& filename) {
    // 🔴 УЯЗВИМОСТЬ: filename не проверяется на path traversal
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return "utf-8";
    
    // Читаем первые 1000 байт и ищем UTF-8 BOM
    char buffer[1000];
    file.read(buffer, sizeof(buffer));
    file.close();
    
    // Простейшая эвристика (всегда возвращает utf-8)
    // 🔴 Настоящая программа должна использовать libicu или что-то подобное
    return "utf-8";
}

// 🚨 УЯЗВИМОСТЬ 3: Нет проверки длины строки, возможен stack overflow при длинном имени
std::vector<User> readData(const std::string& filename) {
    std::vector<User> data;
    std::string encoding = detectEncoding(filename);
    
    // 🔴 УЯЗВИМОСТЬ: Нет проверки, что filename не содержит специальных символов
    // 🔴 УЯЗВИМОСТЬ: Если файл очень большой, читаем его полностью в память
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file " << filename << std::endl;
        return data;
    }
    
    std::string line;
    int line_count = 0;
    while (std::getline(file, line)) {
        line_count++;
        // Удаляем \r в конце
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string part;
        while (std::getline(ss, part, '\t')) {
            parts.push_back(part);
        }
        
        if (parts.size() >= 4) {
            User u;
            u.name = parts[0];
            u.age = parts[1];
            u.address = parts[2];
            u.date = fixDate(parts[3]);
            data.push_back(u);
        } else {
            // 🔴 УЯЗВИМОСТЬ: Информация о структуре файла утекает в stderr
            std::cerr << "[WARN] Line " << line_count << ": expected 4 fields, got " << parts.size() << std::endl;
        }
    }
    file.close();
    return data;
}

std::string shortenName(const std::string& name, int level) {
    // Разделяем имя по пробелам
    std::vector<std::string> parts;
    std::stringstream ss(name);
    std::string part;
    while (ss >> part) parts.push_back(part);
    
    if (level == 0 || parts.size() < 2) return name;
    else if (level == 1) { // Иванов И. И.
        if (parts.size() == 3) {
            return parts[0] + " " + parts[1].substr(0,1) + ". " + parts[2].substr(0,1) + ".";
        } else if (parts.size() == 2) {
            return parts[0] + " " + parts[1].substr(0,1) + ".";
        }
    }
    else if (level == 2) { // Иван. И. И.
        if (parts.size() >= 2) {
            std::string short_last = parts[0].size() > 4 ? parts[0].substr(0,4) + "." : parts[0];
            if (parts.size() == 3) {
                return short_last + " " + parts[1].substr(0,1) + ". " + parts[2].substr(0,1) + ".";
            } else if (parts.size() == 2) {
                return short_last + " " + parts[1].substr(0,1) + ".";
            }
        }
    }
    else if (level >= 3) { // И.И.И.
        std::string initials;
        for (const auto& p : parts) {
            if (!p.empty()) initials += p[0];
            initials += ".";
        }
        return initials;
    }
    return name;
}

// 🚨 УЯЗВИМОСТЬ 4: parse_date_part имеет небезопасные манипуляции со строками
static std::string parseDatePart(const std::string& date_str) {
    std::string clean = date_str;
    // Удаляем кавычки
    if (!clean.empty() && (clean.front() == '"' || clean.front() == '\'')) clean.erase(0,1);
    if (!clean.empty() && (clean.back() == '"' || clean.back() == '\'')) clean.pop_back();
    
    // Форматы для распознавания
    std::vector<std::pair<std::regex, std::string>> formats = {
        {std::regex(R"(^(\d{4})-(\d{1,2})-(\d{1,2})$)"), "%Y-%m-%d"},
        {std::regex(R"(^(\d{4})\.(\d{1,2})\.(\d{1,2})$)"), "%Y.%m.%d"},
        {std::regex(R"(^(\d{4})/(\d{1,2})/(\d{1,2})$)"), "%Y/%m/%d"},
        {std::regex(R"(^(\d{1,2})\.(\d{1,2})\.(\d{4})$)"), "%d.%m.%Y"},
        {std::regex(R"(^(\d{1,2})-(\d{1,2})-(\d{4})$)"), "%d-%m-%Y"},
        {std::regex(R"(^(\d{1,2})/(\d{1,2})/(\d{4})$)"), "%d/%m/%Y"},
    };
    
    for (const auto& [pattern, fmt] : formats) {
        std::smatch match;
        if (std::regex_match(clean, match, pattern)) {
            std::tm tm = {};
            std::stringstream ss(clean);
            ss >> std::get_time(&tm, fmt.c_str());
            if (!ss.fail()) {
                char buffer[11];
                std::strftime(buffer, sizeof(buffer), "%Y-%m-%d", &tm);
                return std::string(buffer);
            }
        }
    }
    
    // 🔴 УЯЗВИМОСТЬ: Нет проверки, что numbers не вызовет переполнение
    std::vector<int> numbers;
    std::regex num_regex(R"(\d+)");
    std::sregex_iterator it(clean.begin(), clean.end(), num_regex);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        numbers.push_back(std::stoi(it->str()));
    }
    
    if (numbers.size() >= 3) {
        int year = -1, month = -1, day = -1;
        for (int n : numbers) {
            if (n >= 1000 && n <= 9999) year = n;
        }
        if (year != -1) {
            std::vector<int> rest;
            for (int n : numbers) if (n != year) rest.push_back(n);
            if (rest.size() >= 2) {
                month = rest[0];
                day = rest[1];
                // Меняем местами, если месяц > 12
                if (month > 12) std::swap(month, day);
                if (month >= 1 && month <= 12 && day >= 1 && day <= 31) {
                    char buffer[11];
                    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d", year, month, day);
                    return std::string(buffer);
                }
            }
        }
    }
    return "";
}

static std::string parseTimePart(const std::string& time_str) {
    std::string clean = time_str;
    // Удаляем миллисекунды и часовые пояса
    std::regex ms_regex(R"(\.\d+)");
    clean = std::regex_replace(clean, ms_regex, "");
    std::regex tz_regex(R"([+-]\d{2}:?\d{2}$)");
    clean = std::regex_replace(clean, tz_regex, "");
    std::regex z_regex(R"(Z$)");
    clean = std::regex_replace(clean, z_regex, "");
    
    std::vector<std::pair<std::regex, std::string>> formats = {
        {std::regex(R"(^(\d{2}):(\d{2}):(\d{2})$)"), "%H:%M:%S"},
        {std::regex(R"(^(\d{2}):(\d{2})$)"), "%H:%M"},
        {std::regex(R"(^(\d{2})(\d{2})(\d{2})$)"), "%H%M%S"},
    };
    
    for (const auto& [pattern, fmt] : formats) {
        std::smatch match;
        if (std::regex_match(clean, match, pattern)) {
            std::tm tm = {};
            std::stringstream ss(clean);
            ss >> std::get_time(&tm, fmt.c_str());
            if (!ss.fail()) {
                char buffer[9];
                std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm);
                return std::string(buffer);
            }
        }
    }
    return "00:00:00";
}

std::string fixDate(const std::string& date_str) {
    std::string cleaned = date_str;
    // Удаляем лишние пробелы
    size_t start = cleaned.find_first_not_of(" \t\n\r");
    if (start != std::string::npos) cleaned = cleaned.substr(start);
    size_t end = cleaned.find_last_not_of(" \t\n\r");
    if (end != std::string::npos) cleaned = cleaned.substr(0, end + 1);
    
    std::string date_part, time_part;
    
    size_t t_pos = cleaned.find('T');
    size_t space_pos = cleaned.find(' ');
    
    if (t_pos != std::string::npos) {
        date_part = cleaned.substr(0, t_pos);
        time_part = t_pos + 1 < cleaned.size() ? cleaned.substr(t_pos + 1) : "";
    } else if (space_pos != std::string::npos) {
        date_part = cleaned.substr(0, space_pos);
        time_part = space_pos + 1 < cleaned.size() ? cleaned.substr(space_pos + 1) : "";
    } else {
        if (cleaned.find(':') != std::string::npos) {
            time_part = cleaned;
        } else {
            date_part = cleaned;
        }
    }
    
    std::string fixed_date = date_part.empty() ? "" : parseDatePart(date_part);
    std::string fixed_time = time_part.empty() ? "00:00:00" : parseTimePart(time_part);
    
    if (!fixed_date.empty()) {
        return fixed_date + " " + fixed_time;
    } else if (!date_part.empty()) {
        // 🔴 УЯЗВИМОСТЬ: Возвращаем исходную строку, которая может содержать опасные символы
        return date_part;
    } else {
        return fixed_time;
    }
}

std::string shortenDate(const std::string& date_str, int level) {
    if (level == 0) return date_str;
    
    size_t space_pos = date_str.find(' ');
    std::string date_part = (space_pos != std::string::npos) ? date_str.substr(0, space_pos) : date_str;
    
    if (level >= 2) {
        // Короткая дата: последние два элемента (MM-DD или DD-MM?)
        size_t last_dash = date_part.rfind('-');
        if (last_dash != std::string::npos) {
            size_t second_last_dash = date_part.rfind('-', last_dash - 1);
            if (second_last_dash != std::string::npos) {
                return date_part.substr(second_last_dash + 1);
            }
        }
        return date_part;
    }
    return date_str;
}

std::string shortenAddress(const std::string& address, int level, int max_len) {
    if (level == 0) return address;
    
    std::string result = address;
    // Замена слов
    auto replace = [&result](const std::string& from, const std::string& to) {
        size_t pos = 0;
        while ((pos = result.find(from, pos)) != std::string::npos) {
            result.replace(pos, from.length(), to);
            pos += to.length();
        }
    };
    
    replace("улица", "ул.");
    replace("проспект", "прс.");
    replace("проезд", "прз.");
    replace("бульвар", "бв.");
    
    // Сокращение города
    size_t comma_pos = result.rfind(',');
    if (comma_pos != std::string::npos) {
        std::string street_part = result.substr(0, comma_pos);
        std::string city = result.substr(comma_pos + 1);
        // Удаляем пробелы в начале города
        size_t city_start = city.find_first_not_of(" ");
        if (city_start != std::string::npos) city = city.substr(city_start);
        
        // Простейшее сокращение города
        if (city.length() > 4) {
            city = city.substr(0, 3) + ".";
        } else if (city.length() > 2) {
            city = city.substr(0, 2) + ".";
        }
        result = street_part + ", " + city;
    }
    
    if (level == 1) {
        std::vector<std::string> words;
        std::stringstream ss(result);
        std::string word;
        while (ss >> word) words.push_back(word);
        if (words.size() > 4) {
            result = "";
            for (size_t i = 0; i < 4 && i < words.size(); ++i) {
                result += words[i] + " ";
            }
            if (!result.empty()) result.pop_back();
        }
    } else if (level >= 2) {
        if (static_cast<int>(result.length()) > max_len) {
            result = result.substr(0, max_len / 2) + "..." + result.substr(result.length() - max_len / 2);
        }
    }
    
    return result;
}

void printTable(const std::vector<User>& data) {
    if (data.empty()) {
        std::cout << "No data to display" << std::endl;
        return;
    }
    
    int max_width = getTerminalWidth();
    std::vector<std::string> headers = {"ФИО", "Возраст", "Адрес", "Дата"};
    std::string table_title = "ТАБЛИЦА ПОЛЬЗОВАТЕЛЕЙ";
    
    // Копируем данные
    std::vector<User> working_data = data;
    
    for (int level = 0; level < 5; ++level) {
        // Применяем сокращения
        for (auto& row : working_data) {
            row.name = shortenName(row.name, level);
            row.date = shortenDate(row.date, level);
            row.address = shortenAddress(row.address, level, 30 - level * 5);
        }
        
        // Вычисляем ширину колонок
        std::vector<int> col_widths = {
            static_cast<int>(headers[0].length()),
            static_cast<int>(headers[1].length()),
            static_cast<int>(headers[2].length()),
            static_cast<int>(headers[3].length())
        };
        
        for (const auto& row : working_data) {
            col_widths[0] = std::max(col_widths[0], static_cast<int>(row.name.length()));
            col_widths[1] = std::max(col_widths[1], static_cast<int>(row.age.length()));
            col_widths[2] = std::max(col_widths[2], static_cast<int>(row.address.length()));
            col_widths[3] = std::max(col_widths[3], static_cast<int>(row.date.length()));
        }
        
        int total_width = col_widths[0] + col_widths[1] + col_widths[2] + col_widths[3] + 3 * 3 + 2;
        
        if (total_width <= max_width || level == 4) {
            // Рисуем таблицу
            auto printLine = [&](char left, char mid, char right, char fill) {
                std::cout << left;
                for (size_t i = 0; i < col_widths.size(); ++i) {
                    std::cout << std::string(col_widths[i] + 2, fill);
                    if (i < col_widths.size() - 1) std::cout << mid;
                }
                std::cout << right << std::endl;
            };
            
            // Заголовок таблицы
            std::string title_display = table_title;
            if (static_cast<int>(title_display.length()) > total_width) {
                title_display = title_display.substr(0, total_width - 3) + "...";
            } else {
                int padding = (total_width - title_display.length()) / 2;
                title_display = std::string(padding, ' ') + title_display + std::string(total_width - title_display.length() - padding, ' ');
            }
            
            std::cout << "+" << std::string(total_width, '-') << "+" << std::endl;
            std::cout << "|" << title_display << "|" << std::endl;
            printLine('+', '+', '+', '-');
            
            // Заголовки колонок
            std::cout << "|";
            for (size_t i = 0; i < headers.size(); ++i) {
                std::cout << " " << headers[i];
                std::cout << std::string(col_widths[i] - headers[i].length() + 1, ' ') << "|";
            }
            std::cout << std::endl;
            printLine('+', '+', '+', '-');
            
            // Данные
            for (const auto& row : working_data) {
                std::cout << "|";
                std::cout << " " << row.name << std::string(col_widths[0] - row.name.length() + 1, ' ') << "|";
                std::cout << " " << row.age << std::string(col_widths[1] - row.age.length() + 1, ' ') << "|";
                std::cout << " " << row.address << std::string(col_widths[2] - row.address.length() + 1, ' ') << "|";
                std::cout << " " << row.date << std::string(col_widths[3] - row.date.length() + 1, ' ') << "|";
                std::cout << std::endl;
            }
            printLine('+', '+', '+', '-');
            break;
        }
        
        // Не влезло — сбрасываем данные и пробуем следующий уровень
        working_data = data;
    }
}