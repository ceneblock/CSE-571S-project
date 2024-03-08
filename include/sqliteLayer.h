#ifndef SQLITELAYER_H
#define SQLITELAYER_H
#include <sqlite3.h> 
#include <string>
#include <map>

class sqlite
{
  public:
    sqlite()
    {
      sqlite3_open("test.db", &db);
      table = "users";
    }

    ~sqlite()
    {
      sqlite3_close(db);
    }

    void init()
    {
      std::string query =
"CREATE TABLE IF NOT EXISTS " + table +"("
"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  host TEXT, user TEXT NOT NULL, password TEXT"
");";
      sqlite3_exec(db, query.c_str(), NULL, 0, NULL);
    }

    void insert(std::map<std::string, std::string> valuesMap)
    {
      std::string query = "insert into " + table + "(";

      //I'm sure there's a better way to do this, but I can't be bothered
      //I want to make sure that key->values are tightly coupled. Otherwise, two
      //vectors would be fine.
      for(auto const &x : valuesMap)
      {
        query += x.first + ",";
      }
      query.pop_back(); //get rid of extra ,
      query += ") values(";
      for(auto const &x : valuesMap)
      {
        query += x.second + ",";
      }
      query.pop_back(); //get rid of extra ,
      query += ");";

      sqlite3_exec(db, query.c_str(), NULL, 0, NULL);
    }
  private:
    sqlite3 *db;
    std::string table;
};
#endif
