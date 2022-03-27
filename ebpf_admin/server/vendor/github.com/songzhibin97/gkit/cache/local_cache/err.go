package local_cache

import "errors"

var (
	CacheExist       = errors.New("local_cache: cache exist")
	CacheNoExist     = errors.New("local_cache: cache no exist")
	CacheExpire      = errors.New("local_cache: cache expire")
	CacheTypeErr = errors.New("local_cache: cache incr type err")
	CacheGobErr      = errors.New("local_cache: cache save gob err")
)

func CacheErrExist(e error) bool {
	return errors.Is(e, CacheExist)
}

func CacheErrNoExist(e error) bool {
	return errors.Is(e, CacheNoExist)
}

func CacheErrExpire(e error) bool {
	return errors.Is(e, CacheExpire)
}

func CacheErrTypeErr(e error) bool {
	return errors.Is(e, CacheTypeErr)
}
