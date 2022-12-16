#define DEBUG

#include "../filter/bloom_filter.hpp"


template <class T, class Allocator, template <class,class> class Container>
bool ReadFileToContainer(std::string file_name, Container<T, Allocator>& container)
{
    std::ifstream fin; 
    fin.open(file_name); 
    if(!fin)
    {
        std::cerr << file_name << " open error" << std::endl;
        exit(EXIT_FAILURE); 
    }
    std::string str;

    while (std::getline(fin, str))
    {
        container.emplace_back(str);
    }
    fin.close(); 
    return true;
}


void test_bloom_filter()
{
    PrintSplitLine('-'); 
    std::cout << "begin the test of bloom filter >>>" << std::endl;
    PrintSplitLine('-'); 

    
    std::vector<std::string> word_list; 
    ReadFileToContainer("word-list-extra-large.txt", word_list); 
    size_t max_element_num = word_list.size();  
    double statistical_security_parameter = 40;
    BloomFilter filter(max_element_num, statistical_security_parameter);

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    //filter.insert(word_list.begin(), word_list.end());    
    filter.Insert(word_list); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "insert #" << word_list.size() << " elements take "   
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;  

    std::cout << "statistical security parameter = " << statistical_security_parameter << std::endl;
    std::cout << double(filter.table_size)/filter.inserted_element_num << " bit per element" << std::endl;
    

    std::cout << "please type the string you want to check, and q to exit >>>" << std::endl; 
    std::string new_str;
    while(true){
        std::getline(std::cin, new_str);
        if(new_str == "q") break;
        if (filter.Contain(new_str) == true) {
            std::cout << new_str <<" is in the set" << std::endl;
        } 
        else{
            std::cout << new_str <<" is not in the set" << std::endl;
        }
    }

    std::string filter_file_name = "filter-1.bloom"; 
    filter.WriteObject(filter_file_name);

    BloomFilter new_filter; 
    new_filter.ReadObject(filter_file_name); 

    std::cout << "please type the string you want to check, and q to exit >>>" << std::endl; 
    while(true){
        std::getline(std::cin, new_str);
        if(new_str == "q") break;
        if (filter.Contain(new_str) == true) {
            std::cout << new_str <<" is in the set" << std::endl;
        } 
        else{
            std::cout << new_str <<" is not in the set" << std::endl;
        }
    }

    PrintSplitLine('-'); 
    std::cout << "finish the test of bloom filter >>>" << std::endl;
    PrintSplitLine('-'); 

}


int main()
{ 
    test_bloom_filter();
    
    return 0;
}
