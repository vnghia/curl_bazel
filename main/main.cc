#include <ctime>
#include <string>
#include <sstream>

#include <utility>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string sha256(const std::string& str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string hmacHex(std::string key, std::string msg)
{
    unsigned char hash[32];

    HMAC_CTX* hmac = HMAC_CTX_new();
    HMAC_Init_ex(hmac, &key[0], static_cast<int>(key.length()), EVP_sha256(), nullptr);
    HMAC_Update(hmac, (unsigned char*)&msg[0], msg.length());
    unsigned int len = 32;
    HMAC_Final(hmac, hash, &len);
    HMAC_CTX_free(hmac);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
    {
        ss << std::hex << std::setw(2) << (unsigned int)hash[i];
    }

    return (ss.str());
}

std::string hmac(std::string key, std::string msg)
{
    unsigned char hash[32];

    HMAC_CTX* hmac = HMAC_CTX_new();
    HMAC_Init_ex(hmac, &key[0], static_cast<int>(key.length()), EVP_sha256(), nullptr);
    HMAC_Update(hmac, (unsigned char*)&msg[0], msg.length());
    unsigned int len = 32;
    HMAC_Final(hmac, hash, &len);
    HMAC_CTX_free(hmac);

    std::stringstream ss;
    ss << std::setfill('0');
    for (size_t i = 0; i < len; i++)
    {
        ss << hash[i];
    }

    return (ss.str());
}

std::pair< std::string, std::string> getAwsIdKey(std::string linkAccessKey) {
    std::string line;
    std::string id;
    std::string accessKey;
    std::ifstream fileAccessKey;
    fileAccessKey.open(linkAccessKey);
    size_t lineCount = {};
    while (std::getline(fileAccessKey, line)) {
        if (++lineCount == 2) {
            size_t deliminator = line.find(',');
            id = line.substr(0, deliminator);
            accessKey = line.substr(deliminator + 1);
        }
    }
    fileAccessKey.close();
    return std::make_pair(id, accessKey);
}

std::string getCanonicalRequest(std::string x_amz_date, std::string hostS3Bucket) {

    std::string canonicalRequest = {};
    canonicalRequest += "GET\n";
    canonicalRequest += "/\n";
    canonicalRequest += "\n";
    canonicalRequest += "host:" + hostS3Bucket + "\n";
    canonicalRequest += "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
    canonicalRequest += "x-amz-date:" + x_amz_date + "\n";
    canonicalRequest += "\n";
    canonicalRequest += "host;x-amz-content-sha256;x-amz-date\n";
    canonicalRequest += "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    return canonicalRequest;
}

std::string getStringToSign(std::string x_amz_date, std::string hostS3Bucket) {

    std::string stringToSign = {};
    stringToSign += "AWS4-HMAC-SHA256\n";
    stringToSign += x_amz_date + "\n";
    stringToSign += x_amz_date.substr(0, 8) + "/eu-west-2/s3/aws4_request\n";
    stringToSign += sha256(getCanonicalRequest(x_amz_date, hostS3Bucket));

    return stringToSign;
}

int main(int argc, char** argv) {

    time_t now;
    struct tm nowTimeInfo;
    char buffer[20];
    time(&now);
    localtime_s(&nowTimeInfo, &now);
    strftime(buffer, sizeof(buffer), "%Y%m%dT%H%M%SZ", &nowTimeInfo);
    std::string x_amz_date(buffer);

    std::string bucketName = "tensorflow-vnvo";
    std::string hostS3Bucket = bucketName + ".s3.amazonaws.com";

    std::pair <std::string, std::string> IdAndKey = getAwsIdKey("C:\\aws\\accessKeys.csv");
    std::string dateKey = hmac("AWS4" + IdAndKey.second, x_amz_date.substr(0, 8));
    std::string regionKey =  hmac(dateKey, "eu-west-2");
    std::string serviceKey = hmac(regionKey, "s3");
    std::string signingKey = hmac(serviceKey, "aws4_request");
    std::string signature = hmacHex(signingKey, getStringToSign(x_amz_date, hostS3Bucket));

    std::string authorizationHeader = {};
    authorizationHeader += "Authorization: AWS4-HMAC-SHA256 ";
    authorizationHeader += "Credential=" + IdAndKey.first + "/" + x_amz_date.substr(0, 8) + "/eu-west-2/s3/aws4_request, ";
    authorizationHeader += "SignedHeaders=host;x-amz-content-sha256;x-amz-date, ";
    authorizationHeader += "Signature=" + signature;

    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, authorizationHeader.c_str());
    headers = curl_slist_append(headers, "x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    headers = curl_slist_append(headers, ("x-amz-date: " + x_amz_date).c_str());


    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, ("https://" + hostS3Bucket).c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        std::cout << "https://" + hostS3Bucket << std::endl;
        std::cout << readBuffer << std::endl;
    }

    return 0;
}
