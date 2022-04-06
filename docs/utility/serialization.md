# Serialization 

## Operator Overloading 
We provide serialization in many places, so we need to overload operator `>>` and `<<` to deal with different input/output stream objects, such as `ElementType` including any C++ POD type, and `std::vector<ElementType>`.
```
template <typename ElementType> std::ofstream &operator<<(std::ofstream &fout, const ElementType& element);
template <typename ElementType> std::ifstream &operator>>(std::ifstream &fin, ElementType& element);

template <typename ElementType> 
std::ofstream &operator<<(std::ofstream &fout, const std::vector<ElementType>& vec_element);
template <typename ElementType> 
std::ifstream &operator>>(std::ifstream &fin, std::vector<ElementType>& vec_element);

template < > std::ofstream &operator<<<std::string>(std::ofstream &fout, const std::string& str);
template < > std::ifstream &operator>><std::string>(std::ifstream &fin, std::string& str);
```

Note: if the input/output stream object is string, it will call the specialized template function. 