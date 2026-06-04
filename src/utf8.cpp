#include <string>
#include <codecvt>
#include <locale>

// 🔴 УЯЗВИМОСТЬ 6: Простая конвертация без проверки валидности UTF-8
std::string toUtf8(const std::string& input) {
    // В реальности должна быть сложная логика
    // Здесь просто возвращаем как есть (предполагая, что вход уже в UTF-8)
    return input;
}