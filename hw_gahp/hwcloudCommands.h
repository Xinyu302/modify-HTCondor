/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#ifndef HWCLOUD_COMMANDS_H
#define HWCLOUD_COMMANDS_H

#include "condor_common.h"
#include "condor_string.h"
#include "MyString.h"
#include "string_list.h"

#include <map>

// EC2 Commands
#define HWCLOUD_COMMAND_VM_START             "EC2_VM_START"
#define HWCLOUD_COMMAND_VM_STOP              "EC2_VM_STOP"
#define HWCLOUD_COMMAND_VM_REBOOT            "EC2_VM_REBOOT"
#define HWCLOUD_COMMAND_VM_STATUS            "EC2_VM_STATUS"
#define HWCLOUD_COMMAND_VM_STATUS_ALL        "EC2_VM_STATUS_ALL"
#define HWCLOUD_COMMAND_VM_RUNNING_KEYPAIR   "EC2_VM_RUNNING_KEYPAIR"
#define HWCLOUD_COMMAND_VM_CREATE_GROUP      "EC2_VM_CREATE_GROUP"
#define HWCLOUD_COMMAND_VM_DELETE_GROUP      "EC2_VM_DELETE_GROUP"
#define HWCLOUD_COMMAND_VM_GROUP_NAMES       "EC2_VM_GROUP_NAMES"
#define HWCLOUD_COMMAND_VM_GROUP_RULES       "EC2_VM_GROUP_RULES"
#define HWCLOUD_COMMAND_VM_ADD_GROUP_RULE    "EC2_VM_ADD_GROUP_RULE"
#define HWCLOUD_COMMAND_VM_DEL_GROUP_RULE    "EC2_VM_DEL_GROUP_RULE"
#define HWCLOUD_COMMAND_VM_CREATE_KEYPAIR    "EC2_VM_CREATE_KEYPAIR"
#define HWCLOUD_COMMAND_VM_DESTROY_KEYPAIR   "EC2_VM_DESTROY_KEYPAIR"
#define HWCLOUD_COMMAND_VM_KEYPAIR_NAMES     "EC2_VM_KEYPAIR_NAMES"
#define HWCLOUD_COMMAND_VM_REGISTER_IMAGE    "EC2_VM_REGISTER_IMAGE"
#define HWCLOUD_COMMAND_VM_DEREGISTER_IMAGE  "EC2_VM_DEREGISTER_IMAGE"
#define HWCLOUD_COMMAND_VM_ASSOCIATE_ADDRESS "EC2_VM_ASSOCIATE_ADDRESS"
#define HWCLOUD_COMMAND_VM_ATTACH_VOLUME     "EC2_VM_ATTACH_VOLUME"
#define HWCLOUD_COMMAND_VM_CREATE_TAGS       "EC2_VM_CREATE_TAGS"
#define HWCLOUD_COMMAND_VM_SERVER_TYPE       "EC2_VM_SERVER_TYPE"

#define HWCLOUD_COMMAND_VM_START_SPOT        "EC2_VM_START_SPOT"
#define HWCLOUD_COMMAND_VM_STOP_SPOT         "EC2_VM_STOP_SPOT"
#define HWCLOUD_COMMAND_VM_STATUS_SPOT       "EC2_VM_STATUS_SPOT"
#define HWCLOUD_COMMAND_VM_STATUS_ALL_SPOT   "EC2_VM_STATUS_ALL_SPOT"

// For condor_annex.
#define HWCLOUD_COMMAND_BULK_START           "EC2_BULK_START"
#define HWCLOUD_COMMAND_PUT_RULE             "CWE_PUT_RULE"
#define HWCLOUD_COMMAND_PUT_TARGETS          "CWE_PUT_TARGETS"
#define HWCLOUD_COMMAND_BULK_STOP            "EC2_BULK_STOP"
#define HWCLOUD_COMMAND_DELETE_RULE          "CWE_DELETE_RULE"
#define HWCLOUD_COMMAND_REMOVE_TARGETS       "CWE_REMOVE_TARGETS"
#define HWCLOUD_COMMAND_GET_FUNCTION         "AWS_GET_FUNCTION"
#define HWCLOUD_COMMAND_S3_UPLOAD            "S3_UPLOAD"
#define HWCLOUD_COMMAND_CF_CREATE_STACK      "CF_CREATE_STACK"
#define HWCLOUD_COMMAND_CF_DESCRIBE_STACKS   "CF_DESCRIBE_STACKS"
#define HWCLOUD_COMMAND_CALL_FUNCTION        "AWS_CALL_FUNCTION"
#define HWCLOUD_COMMAND_BULK_QUERY           "EC2_BULK_QUERY"


#define GENERAL_GAHP_ERROR_CODE             "GAHPERROR"
#define GENERAL_GAHP_ERROR_MSG              "GAHP_ERROR"

class HwcloudRequest {
    public:
        HwcloudRequest( int i, const char * c, int sv = 4 ) :
            includeResponseHeader(false), requestID(i), requestCommand(c),
            signatureVersion(sv), httpVerb( "POST" ) { }
        virtual ~HwcloudRequest();

        virtual bool SendRequest();
        virtual bool SendURIRequest();
        virtual bool SendJSONRequest( const std::string & payload );
        virtual bool SendS3Request( const std::string & payload );

    protected:
        typedef std::map< std::string, std::string > AttributeValueMap;
        AttributeValueMap query_parameters;
        AttributeValueMap headers;

        std::string serviceURL;
        std::string accessKeyFile;
        std::string secretKeyFile;

        std::string errorMessage;
        std::string errorCode;

        std::string resultString;
        unsigned long responseCode;

        bool includeResponseHeader;

		// For tracing.
		int requestID;
		std::string requestCommand;
		struct timespec mutexReleased;
		struct timespec lockGained;
		struct timespec requestBegan;
		struct timespec requestEnded;
		struct timespec mutexGained;
		struct timespec sleepBegan;
		struct timespec liveLine;
		struct timespec sleepEnded;

		// So that we don't bother to send expired signatures.
		struct timespec signatureTime;

		int signatureVersion;

		// For signature v4.  Use if the URL is not of the form
		// '<service>.<region>.provider.tld'.  (Includes S3.)
		std::string region;
		std::string service;

		// Some odd services (Lambda) require the use of GET.
		// Some odd services (S3) requires the use of PUT.
		std::string httpVerb;

	private:
		bool sendV2Request();
		bool sendV4Request( const std::string & payload, bool sendContentSHA = false );

		std::string canonicalizeQueryString();
		bool createV4Signature( const std::string & payload, std::string & authorizationHeader, bool sendContentSHA = false );

		bool sendPreparedRequest(	const std::string & protocol,
									const std::string & uri,
									const std::string & payload );
};

// EC2 Commands

class HwcloudVMStart : public HwcloudRequest {
	public:
		HwcloudVMStart( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudVMStart();

        virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
        std::string instanceID;
        std::vector< std::string > instanceIDs;
};

class HwcloudVMStartSpot : public HwcloudVMStart {
    public:
		HwcloudVMStartSpot( int i, const char * c ) : HwcloudVMStart( i, c ) { }
        virtual ~HwcloudVMStartSpot();

        virtual bool SendRequest();

        static bool ioCheck( char ** argv, int argc );
        static bool workerFunction( char ** argv, int argc, std::string & result_string );

    protected:
        std::string spotRequestID;
};

class HwcloudVMStop : public HwcloudRequest {
	public:
		HwcloudVMStop( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudVMStop();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudVMStopSpot : public HwcloudVMStop {
    public:
		HwcloudVMStopSpot( int i, const char * c ) : HwcloudVMStop( i, c ) { }
        virtual ~HwcloudVMStopSpot();

        // EC2_VM_STOP_SPOT uses the same argument structure as EC2_VM_STOP.
		// static bool ioCheck( char ** argv, int argc );
		static bool workerFunction( char ** argv, int argc, std::string & result_string );
};

#define HWCLOUD_STATUS_RUNNING "running"
#define HWCLOUD_STATUS_PENDING "pending"
#define HWCLOUD_STATUS_SHUTTING_DOWN "shutting-down"
#define HWCLOUD_STATUS_TERMINATED "terminated"

class HwcloudStatusResult {
	public:
		std::string instance_id;
		std::string status;
		std::string ami_id;
		std::string public_dns;
		std::string private_dns;
		std::string keyname;
		std::string instancetype;
        std::string stateReasonCode;
        std::string clientToken;
        std::string spotFleetRequestID;

        std::vector< std::string > securityGroups;
};

class HwcloudVMStatusAll : public HwcloudRequest {
	public:
		HwcloudVMStatusAll( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudVMStatusAll();

        virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
        std::vector< HwcloudStatusResult > results;
};

class HwcloudVMStatus : public HwcloudVMStatusAll {
	public:
		HwcloudVMStatus( int i, const char * c ) : HwcloudVMStatusAll( i, c ) { }
		virtual ~HwcloudVMStatus();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudStatusSpotResult {
    public:
        std::string state;
        std::string launch_group;
        std::string request_id;
        std::string instance_id;
        std::string status_code;
};

class HwcloudVMStatusSpot : public HwcloudVMStatus {
    public:
		HwcloudVMStatusSpot( int i, const char * c ) : HwcloudVMStatus( i, c ) { }
        virtual ~HwcloudVMStatusSpot();

        virtual bool SendRequest();

        // EC2_VM_STATUS_SPOT uses the same argument structure as EC2_VM_STATUS_SPOT.
		// static bool ioCheck( char ** argv, int argc );
		static bool workerFunction( char ** argv, int argc, std::string & result_string );

    protected:
        std::vector< HwcloudStatusSpotResult > spotResults;
};

class HwcloudVMStatusAllSpot : public HwcloudVMStatusSpot {
    public:
		HwcloudVMStatusAllSpot( int i, const char * c ) : HwcloudVMStatusSpot( i, c ) { }
        virtual ~HwcloudVMStatusAllSpot();

		static bool ioCheck( char ** argv, int argc );
		static bool workerFunction( char ** argv, int argc, std::string & result_string );
};

class HwcloudVMCreateKeypair : public HwcloudRequest {
	public:
		HwcloudVMCreateKeypair( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudVMCreateKeypair();

        virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
    	std::string privateKeyFileName;
};

class HwcloudVMDestroyKeypair : public HwcloudRequest {
	public:
		HwcloudVMDestroyKeypair( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudVMDestroyKeypair();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudAssociateAddress : public HwcloudRequest {
    public:
		HwcloudAssociateAddress( int i, const char * c ) : HwcloudRequest( i, c ) { }
        virtual ~HwcloudAssociateAddress();

        static bool ioCheck(char **argv, int argc);
        static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudCreateTags : public HwcloudRequest {
    public:
		HwcloudCreateTags( int i, const char * c ) : HwcloudRequest( i, c ) { }
        virtual ~HwcloudCreateTags();

        static bool ioCheck(char **argv, int argc);
        static bool workerFunction(char **argv, int argc, std::string &result_string);
};

/**
 * HwcloudAttachVolume - Will attempt to attach a running instance to an EBS volume
 * @see http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-AttachVolume.html
 */
class HwcloudAttachVolume : public HwcloudRequest {
    public:
        HwcloudAttachVolume( int i, const char * c ) : HwcloudRequest( i, c ) { }
        virtual ~HwcloudAttachVolume();

        static bool ioCheck(char **argv, int argc);
        static bool workerFunction(char **argv, int argc, std::string &result_string);
};


class HwcloudVMServerType : public HwcloudRequest {
	public:
        HwcloudVMServerType( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudVMServerType();

		virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

	protected:
		std::string serverType;
};

// Spot Fleet commands
class HwcloudBulkStart : public HwcloudRequest {
	public:
		HwcloudBulkStart( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudBulkStart();

        virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
    	void setLaunchSpecificationAttribute( int, std::map< std::string, std::string > &, const char *, const char * = NULL );

		std::string bulkRequestID;
};

class HwcloudBulkStop : public HwcloudRequest {
	public:
		HwcloudBulkStop( int i, const char * c ) : HwcloudRequest( i, c ), success( true ) { }
		virtual ~HwcloudBulkStop();

        virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

	protected:
		bool success;
};

class HwcloudPutRule : public HwcloudRequest {
	public:
		HwcloudPutRule( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudPutRule();

		virtual bool SendJSONRequest( const std::string & payload );

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
		std::string ruleARN;
};

class HwcloudDeleteRule : public HwcloudRequest {
	public:
		HwcloudDeleteRule( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudDeleteRule();

		virtual bool SendJSONRequest( const std::string & payload );

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudPutTargets : public HwcloudRequest {
	public:
		HwcloudPutTargets( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudPutTargets();

		virtual bool SendJSONRequest( const std::string & payload );

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudRemoveTargets : public HwcloudRequest {
	public:
		HwcloudRemoveTargets( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudRemoveTargets();

		virtual bool SendJSONRequest( const std::string & payload );

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);
};

class HwcloudGetFunction : public HwcloudRequest {
	public:
		HwcloudGetFunction( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudGetFunction();

		virtual bool SendURIRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
		std::string functionHash;
};

class HwcloudS3Upload : public HwcloudRequest {
	public:
		HwcloudS3Upload( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudS3Upload();

		virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

	protected:
		std::string path;
};

class HwcloudCreateStack : public HwcloudRequest {
	public:
		HwcloudCreateStack( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudCreateStack();

		virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

	protected:
		std::string stackID;
};

class HwcloudDescribeStacks : public HwcloudRequest {
	public:
		HwcloudDescribeStacks( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudDescribeStacks();

		virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

	protected:
		std::string stackStatus;
		std::vector< std::string > outputs;
};

class HwcloudCallFunction : public HwcloudRequest {
	public:
		HwcloudCallFunction( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudCallFunction();

		virtual bool SendJSONRequest( const std::string & payload );

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

    protected:
    	std::string success;
		std::string instanceID;
};

class HwcloudBulkQuery : public HwcloudRequest {
	public:
		HwcloudBulkQuery( int i, const char * c ) : HwcloudRequest( i, c ) { }
		virtual ~HwcloudBulkQuery();

        virtual bool SendRequest();

		static bool ioCheck(char **argv, int argc);
		static bool workerFunction(char **argv, int argc, std::string &result_string);

	protected:
		StringList resultList;
};

#endif

