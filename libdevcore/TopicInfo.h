/**
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
 *
 * @brief: topic item info
 *
 * @file: TopicInfo.h
 * @author: darrenyin
 * @date 2019-08-07
 */
#pragma once
#include <string>
namespace dev
{
enum TopicStatus
{
    VERIFYING_STATUS = 0,  // init status,for topic which  needs to cert before cert operation has
                           // been finished
    VERIFYI_SUCCESS_STATUS = 1,  // verify success status,for topic which not need to cert or cert
                                 // operation has been finished  with ok result
    VERIFYI_FAILED_STATUS = 2,   // verify failed status, for topic which cert operation has been
                                 // finished with not ok result
};

enum ChannelMessageType
{
    CHANNEL_RPC_REQUEST = 0x12,        // type for rpc request
    CLIENT_HEARTBEAT = 0x13,           // type for heart beat for sdk
    CLIENT_HANDSHAKE = 0x14,           // type for hand shake
    CLIENT_REGISTER_EVENT_LOG = 0x15,  // type for event log filter register request and response
    AMOP_REQUEST = 0x30,               // type for request from sdk
    AMOP_RESPONSE = 0x31,              // type for response to sdk
    AMOP_CLIENT_TOPICS = 0x32,         // type for topic request
    AMOP_MULBROADCAST = 0x35,          // type for mult broadcast
    REQUEST_TOPICCERT = 0x37,          // type request verify
    UPDATE_TOPIICSTATUS = 0x38,        // type for update status
    TRANSACTION_NOTIFY = 0x1000,       // type for  transaction notify
    BLOCK_NOTIFY = 0x1001,             // type for  block notify
    EVENT_LOG_PUSH = 0x1002            // type for event log push
};

class TopicItem
{
public:
    std::string topic;
    TopicStatus topicStatus;

public:
    TopicItem() : topicStatus(VERIFYING_STATUS) {}
    bool operator<(const TopicItem& item) const { return this->topic < item.topic; }
};
const std::string topicNeedVerifyPrefix = "#!$TopicNeedVerify_";
const std::string verifyChannelPrefix = "#!$VerifyChannel_";
const std::string pushChannelPrefix = "#!$PushChannel_";
}  // namespace dev