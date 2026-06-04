#!/bin/bash
echo "🔨 Rebuilding Formatter C++..."

# Удаляем старую сборку
rm -rf build

# Создаем папку сборки
mkdir build
cd build

# Запускаем CMake и сборку
cmake ..
make -j$(nproc)

# Проверяем успешность сборки
if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo "   Run with: ./formatter_cpp -i ../data/users.txt"
    echo "   Or from URL: ./formatter_cpp -i https://example.com/data.txt"
else
    echo "❌ Build failed!"
    exit 1
fi