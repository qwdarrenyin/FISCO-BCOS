/*
 * @CopyRight:
 * FISCO-BCOS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FISCO-BCOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>
 * (c) 2016-2019 fisco-dev contributors.
 */
/** @file test_BasicRocksDB.cpp
 *  @author yujiechen
 *  @date 2010-06-26
 */
#include <libconfig/GlobalConfigure.h>
#include <libledger/DBInitializer.h>
#include <libledger/LedgerParam.h>
#include <libstorage/BasicRocksDB.h>
#include <boost/test/unit_test.hpp>
using namespace dev;
using namespace dev::ledger;
using namespace dev::db;
using namespace rocksdb;

BOOST_AUTO_TEST_SUITE(TestRocksDB)

std::shared_ptr<BasicRocksDB> openTable(
    std::shared_ptr<BasicRocksDB> basicRocksDB, std::string const& dbName)
{
    rocksdb::Options options;
    options.IncreaseParallelism(std::max(1, (int)std::thread::hardware_concurrency()));
    options.OptimizeLevelStyleCompaction();
    options.create_if_missing = true;
    options.max_open_files = 1000;
    options.compression = rocksdb::kSnappyCompression;
    // open rocksDB with default option
    auto dbHandler = basicRocksDB->Open(options, dbName);
    if (dbHandler)
    {
        return basicRocksDB;
    }
    return nullptr;
}

// test get value
void testReGetValue(std::shared_ptr<BasicRocksDB> basicRocksDB, std::string const& keyPrefix,
    std::string const& valuePrefix, std::string const& dbName, size_t const& succNum,
    bool needOpen = true)
{
    LOG(DEBUG) << LOG_DESC("testReGetValue");
    // open DB
    if (needOpen)
    {
        auto dbHandler = openTable(basicRocksDB, dbName);
        BOOST_CHECK(dbHandler != nullptr);
    }
    std::string value;
    for (size_t i = 0; i < succNum; i++)
    {
        std::string key = keyPrefix + std::to_string(i);
        auto dbStatus = basicRocksDB->Get(rocksdb::ReadOptions(), key, value);
        BOOST_CHECK(dbStatus.ok());
        BOOST_CHECK(value == valuePrefix + std::to_string(i));
    }
}

std::shared_ptr<BasicRocksDB> testBasicOperation(std::shared_ptr<BasicRocksDB> basicRocksDB,
    std::string const& dbName, std::string const& keyPrefix, std::string const& valuePrefix,
    size_t& succNum)
{
    // open table
    auto dbHandler = openTable(basicRocksDB, dbName);
    if (!dbHandler)
    {
        return nullptr;
    }
    std::string key = keyPrefix;
    std::string value = valuePrefix;
    ROCKSDB_LOG(DEBUG) << LOG_DESC("* Check get non-exist key from rocksDB");
    // get a non-exist key
    auto dbStatus = basicRocksDB->Get(rocksdb::ReadOptions(), key, value);
    BOOST_CHECK(dbStatus.IsNotFound() == true);
    BOOST_CHECK(value == valuePrefix);

    ROCKSDB_LOG(DEBUG) << LOG_DESC("* Check Write and Get value from DB");
    // put the key value into batch
    rocksdb::WriteBatch batch;
    succNum = 0;
    for (size_t i = 0; i < 10; i++)
    {
        value = valuePrefix + std::to_string(succNum);
        key = keyPrefix + std::to_string(succNum);
        dbStatus = basicRocksDB->Put(batch, key, value);
        if (dbStatus.ok())
        {
            succNum++;
            BOOST_CHECK((size_t)batch.Count() == succNum);
        }
    }
    // write batch into DB
    basicRocksDB->Write(rocksdb::WriteOptions(), batch);
    // check Get
    testReGetValue(basicRocksDB, keyPrefix, valuePrefix, dbName, succNum, false);
    return basicRocksDB;
}

void testAllDBOperation(
    std::string const& dbName, std::string const& keyPrefix, std::string const& valuePrefix)
{
    size_t succNum;
    // open table succ
    std::shared_ptr<BasicRocksDB> basicRocksDB = std::make_shared<BasicRocksDB>();
    auto handler = testBasicOperation(basicRocksDB, dbName, keyPrefix, valuePrefix, succNum);
    if (handler)
    {
        BOOST_CHECK(succNum > 0);
        // test reopen table
        basicRocksDB->closeDB();
        testReGetValue(basicRocksDB, keyPrefix, valuePrefix, dbName, succNum, true);
    }
}

// test write and read value from rocksDB
BOOST_AUTO_TEST_CASE(testWriteAndReadValue)
{
    std::string dbName = "test_rocksDB";

    std::string keyPrefix = "test_key";
    std::string valuePrefix = "test_value";
    testAllDBOperation(dbName, keyPrefix, valuePrefix);
    boost::filesystem::remove_all(dbName);
}

// test dbOperation with hook handler(encryption and decryption)
BOOST_AUTO_TEST_CASE(testWithEncryptDecryptHandler)
{
    // fake param
    std::string dbName = "test_db/RocksDB";
    std::shared_ptr<LedgerParam> param = std::make_shared<LedgerParam>();
    param->mutableStorageParam().path = dbName;

    // init DB initializer
    std::shared_ptr<DBInitializer> dbInitializer = std::make_shared<DBInitializer>(param);

    // init for disk encryption
    // enable disk encryption
    g_BCOSConfig.diskEncryption.enable = true;
    // set datakey
    g_BCOSConfig.diskEncryption.dataKey = "313233343536";

    // init rocksDB, open db and set handler for DB
    std::shared_ptr<BasicRocksDB> basicRocksDB = dbInitializer->initBasicRocksDB();

    BOOST_CHECK(basicRocksDB != nullptr);

    // test db operation
    std::string keyPrefix = "test_encKey";
    std::string valuePrefix = "value_encValue";
    testAllDBOperation(dbName, keyPrefix, valuePrefix);
    boost::filesystem::remove_all(dbName);
    // disable disk encryption
    g_BCOSConfig.diskEncryption.enable = false;
}

BOOST_AUTO_TEST_SUITE_END()