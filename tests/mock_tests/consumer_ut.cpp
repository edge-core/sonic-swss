#include "ut_helper.h"
#include "mock_orchagent_main.h"
#include "mock_table.h"

#include <sstream>
#include <unistd.h>  /* pipe(), close() */
#include "select.h" /* swss::Select */

extern PortsOrch *gPortsOrch;

namespace consumer_test
{
    using namespace std;

    // -----------------------------------------------------------------------
    // MockSelectable: lightweight Selectable backed by a real pipe(2) fd so
    // that Select::addSelectable() / epoll_ctl() succeed without Redis.
    //
    // initializedWithData() returns true → the object is inserted into
    // Select::m_ready immediately at addSelectable() time, without waiting
    // for an epoll_wait() event.  This lets us pre-populate m_ready with
    // multiple items at controlled priorities and then drain them with
    // select(timeout=0) to verify the priority-sorted dispatch order.
    // -----------------------------------------------------------------------
    class MockSelectable : public swss::Selectable
    {
    public:
        MockSelectable(int pri, const std::string &name)
            : swss::Selectable(pri), m_name(name), m_hasData(true)
        {
            if (pipe(m_fds) != 0)
                throw std::runtime_error("pipe() failed in MockSelectable");
        }

        ~MockSelectable()
        {
            close(m_fds[0]);
            close(m_fds[1]);
        }

        int      getFd()             override { return m_fds[0]; }
        uint64_t readData()          override { return 0; }
        bool     hasData()           override { return m_hasData; }
        bool     hasCachedData()     override { return false; }
        bool     initializedWithData() override { return m_hasData; }
        void     updateAfterRead()   override { m_hasData = false; }

        const std::string &name() const { return m_name; }

    private:
        int         m_fds[2];
        std::string m_name;
        bool        m_hasData;
    };

    class TestOrch : public Orch
    {
    public:
        TestOrch(swss::DBConnector *db, string tableName)
            :Orch(db, tableName),
            m_notification_count(0)
        {
        }

        void doTask(Consumer& consumer)
        {
            std::cout << "TestOrch::doTask " << consumer.m_toSync.size() << std::endl;
            m_notification_count += consumer.m_toSync.size();
            consumer.m_toSync.clear();
        }

        long m_notification_count;
    };
    struct ConsumerTest : public ::testing::Test
    {
        shared_ptr<swss::DBConnector> m_app_db;
        shared_ptr<swss::DBConnector> m_config_db;
        shared_ptr<swss::DBConnector> m_state_db;

        string key = "key";
        string f1 = "field1";
        string v1a = "value1_a";
        string v1b = "value1_b";
        string f2 = "field2";
        string v2a = "value2_a";
        string v2b = "value2_b";
        string f3 = "field3";
        string v3a = "value3_a";
        KeyOpFieldsValuesTuple exp_kofv;

        unique_ptr<Consumer> consumer;
        deque <KeyOpFieldsValuesTuple> kofv_q;

        ConsumerTest()
        {
            // FIXME: move out from constructor
            m_app_db = make_shared<swss::DBConnector>("APPL_DB", 0);
            m_config_db = make_shared<swss::DBConnector>("CONFIG_DB", 0);
            m_state_db = make_shared<swss::DBConnector>("STATE_DB", 0);
            consumer = unique_ptr<Consumer>(new Consumer(
                new swss::ConsumerStateTable(m_config_db.get(), "CFG_TEST_TABLE", 1, 1), gPortsOrch, "CFG_TEST_TABLE"));
        }

        virtual void SetUp() override
        {
            ::testing_db::reset();
        }

        virtual void TearDown() override
        {
            ::testing_db::reset();
        }

        void validate_syncmap(SyncMap &sync, uint16_t exp_sz, std::string exp_key, KeyOpFieldsValuesTuple exp_kofv)
        {
            // verify the content in syncMap
            ASSERT_EQ(sync.size(), exp_sz);
            auto it = sync.begin();
            while (it != sync.end())
            {
                KeyOpFieldsValuesTuple t = it->second;

                string itkey = kfvKey(t);
                if (itkey == exp_key) {
                    ASSERT_EQ(t, exp_kofv);
                    it = sync.erase(it);
                    break;
                } else {
                    it++;
                }
            }
            ASSERT_EQ(sync.size(), exp_sz-1);
        }
    };

    TEST_F(ConsumerTest, ConsumerAddToSync_Set)
    {

        // Test case, one set_command
        auto entry = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        kofv_q.push_back(entry);
        consumer->addToSync(kofv_q);
        exp_kofv = entry;
        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Del)
    {
        // Test case, one with del_command
        auto entry = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        kofv_q.push_back(entry);
        consumer->addToSync(kofv_q);

        exp_kofv = entry;
        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);

    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Set_Del)
    {
        // Test case, add SET then DEL
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        kofv_q.push_back(entrya);
        kofv_q.push_back(entryb);
        consumer->addToSync(kofv_q);

        // expect only DEL
        exp_kofv = entryb;
        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Del_Set)
    {
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        // Test case, add DEL then SET, re-try 100 times, order should be kept
        for (auto x = 0; x < 100; x++)
        {
            kofv_q.push_back(entrya);
            kofv_q.push_back(entryb);
            consumer->addToSync(kofv_q);

            // expect DEL then SET
            exp_kofv = entrya;
            validate_syncmap(consumer->m_toSync, 2, key, exp_kofv);

            exp_kofv = entryb;
            validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
        }
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Set_Del_Set_Multi)
    {
        // Test5, add SET, DEL then SET, re-try 100 times , order should be kept
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        auto entryc = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        for (auto x = 0; x < 100; x++)
        {
            kofv_q.push_back(entrya);
            kofv_q.push_back(entryb);
            kofv_q.push_back(entryc);
            consumer->addToSync(kofv_q);

            // expect DEL then SET
            exp_kofv = entryb;
            validate_syncmap(consumer->m_toSync, 2, key, exp_kofv);

            exp_kofv = entryc;
            validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
        }
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Set_Del_Set_Multi_In_Q)
    {
        // Test5, add SET, DEL then SET, repeat 100 times in queue, final result and order should be kept
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        auto entryc = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        for (auto x = 0; x < 100; x++)
        {
            kofv_q.push_back(entrya);
            kofv_q.push_back(entryb);
            kofv_q.push_back(entryc);
        }
        consumer->addToSync(kofv_q);

        // expect DEL then SET
        exp_kofv = entryb;
        validate_syncmap(consumer->m_toSync, 2, key, exp_kofv);

        exp_kofv = entryc;
        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Del_Set_Setnew)
    {
        // Test case, DEL, SET, then SET with different value
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        auto entryc = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1b },
                    { f2, v2b } } });

        kofv_q.push_back(entrya);
        kofv_q.push_back(entryb);
        kofv_q.push_back(entryc);
        consumer->addToSync(kofv_q);

        // expect DEL then SET with new values
        exp_kofv = entrya;
        validate_syncmap(consumer->m_toSync, 2, key, exp_kofv);

        exp_kofv = entryc;
        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Del_Set_Setnew1)
    {
        // Test case, DEL, SET, then SET with new values and new fields
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        auto entryc = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1b },
                    { f3, v3a } } });

        kofv_q.push_back(entrya);
        kofv_q.push_back(entryb);
        kofv_q.push_back(entryc);
        consumer->addToSync(kofv_q);

        // expect DEL then SET with new values and new fields
        exp_kofv = entrya;
        validate_syncmap(consumer->m_toSync, 2, key, exp_kofv);

        exp_kofv = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f2, v2a },
                    { f1, v1b },
                    { f3, v3a } } });

        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);
    }

    TEST_F(ConsumerTest, ConsumerAddToSync_Ind_Set_Del)
    {
        // Test case,  Add individuals by addToSync, SET then DEL
        auto entrya = KeyOpFieldsValuesTuple(
            { key,
                SET_COMMAND,
                { { f1, v1a },
                    { f2, v2a } } });

        auto entryb = KeyOpFieldsValuesTuple(
            { key,
                DEL_COMMAND,
                { { } } });

        consumer->addToSync(entrya);
        consumer->addToSync(entryb);

        // expect only DEL
        exp_kofv = entryb;
        validate_syncmap(consumer->m_toSync, 1, key, exp_kofv);

    }

    // This test verifies that the Executor-layer priority matches the value
    // passed to addConsumer().
    TEST_F(ConsumerTest, AddConsumer_ExecutorPriorityPropagated)
    {
        const int kTestPri = 42;

        // PriTestOrch uses Orch(db, tableName, pri) ctor which calls
        // addConsumer(db, tableName, pri) internally.
        struct PriTestOrch : public Orch
        {
            PriTestOrch(swss::DBConnector *db, const string &tbl, int pri)
                : Orch(db, tbl, pri) {}
            void doTask(Consumer &c) override { c.m_toSync.clear(); }
        };

        PriTestOrch orch(m_app_db.get(), "APPL_PRIO_TABLE", kTestPri);
        Executor *executor = orch.getExecutor("APPL_PRIO_TABLE");

        ASSERT_NE(executor, nullptr);
        // The Consumer Executor priority must equal kTestPri.
        // Before the fix this returned 0 regardless of the requested priority.
        EXPECT_EQ(executor->getPri(), kTestPri);
    }

    // This test verifies that a single execute() with an empty key-set drains
    // the entire inflated counter, leaving hasData() == false.
    TEST_F(ConsumerTest, ConsumerExecute_DrainsInflatedQueueLength)
    {
        const long long kInflatedQueueLen = 500;

        TestOrch test_orch(m_config_db.get(), "CFG_DRAIN_TABLE");
        // Create a standalone ConsumerStateTable and Consumer for this test.
        // The table is backed by an empty mock DB so pops() returns nothing.
        auto *table = new swss::ConsumerStateTable(
            m_config_db.get(), "CFG_DRAIN_TABLE", 1, 1);
        Consumer test_consumer(table, &test_orch, "CFG_DRAIN_TABLE");

        // Ensure the mock key-set is empty so pops() returns an empty deque.
        ::testing_db::reset();

        // Artificially inflate m_queueLength to simulate a PUBLISH burst whose
        // notifications outpace the key consumption by pops().
        table->setQueueLength(kInflatedQueueLen);
        ASSERT_TRUE(test_consumer.hasData());
        ASSERT_TRUE(test_consumer.hasCachedData());

        // A single execute() must drain the entire inflated counter.
        test_consumer.execute();

        // After the fix m_queueLength == 0: the consumer is removed from
        // Select::m_ready, stopping the idle-spin that starved other consumers.
        EXPECT_FALSE(test_consumer.hasData());
        EXPECT_FALSE(test_consumer.hasCachedData());
    }


    // This test validates the full Select::m_ready ordering path:
    //
    //   addConsumer(pri=X)  →  consumer->setPri(X)  →  Executor::getPri()==X
    //                       →  Select::m_ready sorted by getPri() desc
    //                       →  select() returns highest-priority object first
    TEST_F(ConsumerTest, SelectPriorityOrder_HigherPriorityFirstDispatched)
    {
        swss::Select sel;

        // Create three selectables with distinct priorities.
        MockSelectable low  ( 5, "low_pri_5");
        MockSelectable mid  (20, "mid_pri_20");
        MockSelectable high (200, "high_pri_200");

        // Register in intentionally reverse-priority order to prove that
        // dispatch order depends on priority, not insertion order.
        sel.addSelectable(&low);
        sel.addSelectable(&high);
        sel.addSelectable(&mid);

        // All three objects are now in Select::m_ready (via initializedWithData()).
        // select(timeout=0) polls epoll immediately (returns 0 new fd events)
        // and then drains m_ready in priority-sorted order.
        std::vector<std::string> dispatch_order;
        swss::Selectable *s = nullptr;
        int ret;

        ret = sel.select(&s, 0);
        ASSERT_EQ(ret, swss::Select::OBJECT);
        dispatch_order.push_back(static_cast<MockSelectable*>(s)->name());

        ret = sel.select(&s, 0);
        ASSERT_EQ(ret, swss::Select::OBJECT);
        dispatch_order.push_back(static_cast<MockSelectable*>(s)->name());

        ret = sel.select(&s, 0);
        ASSERT_EQ(ret, swss::Select::OBJECT);
        dispatch_order.push_back(static_cast<MockSelectable*>(s)->name());

        // Fourth call must return TIMEOUT — m_ready is empty.
        ret = sel.select(&s, 0);
        EXPECT_EQ(ret, swss::Select::TIMEOUT);

        // Highest priority (200) must be dispatched first, lowest (5) last.
        ASSERT_EQ(dispatch_order.size(), 3u);
        EXPECT_EQ(dispatch_order[0], "high_pri_200");
        EXPECT_EQ(dispatch_order[1], "mid_pri_20");
        EXPECT_EQ(dispatch_order[2], "low_pri_5");
    }
}
