#define DEBUG
#define OMP

#include "../filter/cuckoo_filter.hpp"
#include "../utility/print.hpp"

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


void test_cuckoo_filter()
{
    PrintSplitLine('-'); 
    std::cout << "begin the test of cuckoo filter >>>" << std::endl;
    PrintSplitLine('-'); 

    
    std::vector<std::string> word_list; 
    ReadFileToContainer("word-list-extra-large.txt", word_list); 
    size_t projected_element_num = word_list.size();  
    double desired_false_positive_probability = 1/pow(2, 10);
    CuckooFilter filter(projected_element_num, desired_false_positive_probability);

    filter.PrintInfo();

    //if(filter.Insert("cuckoo") == true) std::cout << "success" << std::endl; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    //filter.insert(word_list.begin(), word_list.end());    
    filter.Insert(word_list); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "insert #" << word_list.size() << " elements take "   
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;  

    filter.PrintInfo();

    // std::cout << "false positive probability = " << desired_false_positive_probability << std::endl;
    // std::cout << double(filter.table_size)/filter.inserted_element_num << " bit per element" << std::endl;
    
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

    std::string filter_file_name = "filter.cuckoo"; 
    filter.WriteObject(filter_file_name);

    CuckooFilter filter1; 
    filter1.ReadObject(filter_file_name); 

    std::cout << "please type the string you want to check, and q to exit >>>" << std::endl; 
    while(true){
        std::getline(std::cin, new_str);
        if(new_str == "q") break;
        if (filter1.Contain(new_str) == true) {
            std::cout << new_str <<" is in the set" << std::endl;
        } 
        else{
            std::cout << new_str <<" is not in the set" << std::endl;
        }
    }

    char *buffer = new char[filter.ObjectSize()]; 
    filter.WriteObject(buffer);

    CuckooFilter filter2;
    filter2.ReadObject(buffer);  

    std::cout << "please type the string you want to check, and q to exit >>>" << std::endl; 
    while(true){
        std::getline(std::cin, new_str);
        if(new_str == "q") break;
        if (filter2.Contain(new_str) == true) {
            std::cout << new_str <<" is in the set" << std::endl;
        } 
        else{
            std::cout << new_str <<" is not in the set" << std::endl;
        }
    }

    delete[] buffer;


    PrintSplitLine('-'); 
    std::cout << "finish the test of cuckoo filter >>>" << std::endl;
    PrintSplitLine('-'); 

}


int main()
{ 
    test_cuckoo_filter();
    
    return 0;
}
