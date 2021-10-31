#define DEBUG
#define OMP

#include "../filter/bloom_filter.hpp"
#include "../utility/print.hpp"

template <class T, class Allocator, template <class,class> class Container>
bool ReadFile(std::string file_name, Container<T, Allocator>& c)
{
    std::ifstream fin; 
    fin.open(file_name); 
    if(!fin)
    {
        std::cerr << file_name << " open error" << std::endl;
        exit(1); 
    }
    std::string str;

    while (std::getline(fin, str))
    {
        c.emplace_back(str);
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
    ReadFile("word-list-extra-large.txt", word_list); 
    size_t projected_element_num = word_list.size();  
    double desired_false_positive_probability = 1/pow(2, 10);
    BloomFilter<uint32_t> filter(projected_element_num, desired_false_positive_probability);

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    //filter.insert(word_list.begin(), word_list.end());    
    filter.insert(word_list); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "insert #" << word_list.size() << " elements take "   
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;  

    std::cout << "false positive probability = " << desired_false_positive_probability << std::endl;
    std::cout << double(filter.table_size)/filter.inserted_element_num << " bit per element" << std::endl;
    

    std::cout << "please type the string you want to check, and q to exit >>>" << std::endl; 
    std::string new_str;
    while(true){
        std::getline(std::cin, new_str);
        if(new_str == "q") break;
        if (filter.contain(new_str) == true) {
            std::cout << new_str <<" is in the set" << std::endl;
        } 
        else{
            std::cout << new_str <<" is not in the set" << std::endl;
        }
    }

    std::string filter_file_name = "filter-1.bloom"; 
    filter.writeobject(filter_file_name);

    BloomFilter<uint32_t> new_filter; 
    new_filter.readobject(filter_file_name); 

    std::cout << "please type the string you want to check, and q to exit >>>" << std::endl; 
    while(true){
        std::getline(std::cin, new_str);
        if(new_str == "q") break;
        if (filter.contain(new_str) == true) {
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
