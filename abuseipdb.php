<?php
defined('_JEXEC') or die;

/**
 * AbuseIPDB system plugin
 *
 */
class plgSystemAbuseipdb extends JPlugin
{
    /**
     * Constructor.
     *
     * @param   object  &$subject  The object to observe.
     * @param   array   $config	An optional associative array of configuration settings.
     *
     * @since   1.0
     */
    public function __construct(&$subject, $config)
    {
        // Calling the parent Constructor
        parent::__construct($subject, $config);
        // Include the JLog class.
        jimport('joomla.log.log');
        //Setup logger
        JLog::addLogger(
            array(
                'logger' => 'database',
                'db_table' => '#__abuseipdb_entries'
            ),
            JLog::ALL,
            array(
                'abuseipdb_blocked_ip',
                'abuseipdb_cache_blocked_ip',
                'abuseipdb_blacklist_blocked_ip')
        );

    }

    /**
     * Listener for the `onAfterInitialise` event
     *
     * @return  void
     *
     * @since   1.0
     */
    public function onAfterInitialise()
    {

        //Getting params
        $APIkey = $this->params->get('APIkey', '');
        $lookup_period = $this->params->get('lookup_period', '30');
        $min_attempts = $this->params->get('min_attempts', '1');
        $whitelist_array = preg_split("/\r\n|\n|\r/", $this->params->get('whitelist'));
        $blacklist_array = preg_split("/\r\n|\n|\r/", $this->params->get('blacklist'));
        $cache_time = $this->params->get('cache_time', '3');

        //Retrive visitors IP
        $IP = $this->getIP();

        //if visitors IP is in whitelist we jump out
        if($this->params->get('whitelist') !== '' && in_array($IP,$whitelist_array) ){
            return true;
        }


        //if visitors IP is in blacklist, we block them
        if($this->params->get('blacklist') !== '' && in_array($IP,$blacklist_array) ){
            //Logging it to database
            JLog::add($IP, JLog::INFO, 'abuseipdb_blacklist_blocked_ip');
            //Block'em
            header('HTTP/1.1 403 Forbidden');
            jexit();
        }

        //Do we have the IP in cache?
        $cached = $this->get_cached($IP,$cache_time);
        //Was it found in cache?
        if(is_object($cached)){
            //Has it allready been blocked?
            if($cached->blocked) {
                //update cache and log it and block it
                $this->update_cache($IP, true, $cached);
                JLog::add($IP, JLog::INFO, 'abuseipdb_cache_blocked_ip');
                //Block'em
                header('HTTP/1.1 403 Forbidden');
                jexit();
            }else{
                //We have them in cache and it was not blocked.
                // Updating cache and jumping out
                $this->update_cache($IP, false, $cached);
                return true;
            }
        }

        //Not in cache? lets look it up in AbuseIPDB
        $http = JHttpFactory::getHttp();
        //try to connect and look it up in AbuseIPDB.
        try {
            $response = $http->get('https://www.abuseipdb.com/check/' . $IP . '/json?key=' . $APIkey . '&days=' . $lookup_period, null, 2);
        }catch (Exception $e){
            //Whoops! couldn't connect to abuseipdb. Jumping out and we try again next time.
            return true;
        }
        $response = $http->get('https://www.abuseipdb.com/check/'.$IP.'/json?key='.$APIkey.'&days='.$lookup_period);
        // Did we get a connection?
        if($response->code == 200){
            //Converting JSON response body to array
            $abusearray = json_decode($response->body);
            //Count how many times the IP is registered
            $registered_attempts = count($abusearray);
            //Is it registered more times than we accepts?
            if($registered_attempts >= $min_attempts){
                //caching it
                $this->update_cache($IP, true);
                //Logging it to database
                JLog::add($IP, JLog::INFO, 'abuseipdb_blocked_ip');
                //Block'em
                header('HTTP/1.1 403 Forbidden');
                jexit();
            }else{
                //they are allowed to pass, lets cache it
                $this->update_cache($IP, false);
            }
        }
    }

    private function get_cached($IP,$cache_time = 1){
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);
        $query->select('*');
        $query->from($db->quoteName('#__abuseipdb_cache'));
        $query->where($db->quoteName('IP')." = ".$db->quote($IP),'AND');
        $query->where($db->quoteName('date')." > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ".$cache_time." HOUR) ");
        $db->setQuery($query);
        $result = $db->loadObject();
        return $result;

    }

    private function update_cache($IP, $blockit = false , $object = NULL){
        $date = new JDate();
        $cache_object = new stdClass();
        $db = JFactory::getDbo();

        //Are we updating cache entry?
        if(is_object($object)){
            $cache_object = clone $object;
            // If we are updating, we just updates the datetime
            $cache_object->date = $date->toSql();

        }else{
            $cache_object->IP = $IP;
            $cache_object->date = $date->toSql();
            if($blockit){
                $cache_object->blocked = 1;
            }else{
                $cache_object->blocked = 0;
            }
        }

        $sql = "REPLACE INTO ".$db->quoteName('#__abuseipdb_cache')."(IP,blocked,date) ";
        $sql .= " VALUES(".$db->quote($cache_object->IP).",".$cache_object->blocked.",".$db->quote($cache_object->date).");";

        $db->setQuery($sql);
        $result = $db->execute();
        return $result;

    }



    private function getIP() {
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] && (!isset($_SERVER['REMOTE_ADDR']) || preg_match('/^127\..*/i', trim($_SERVER['REMOTE_ADDR'])) || preg_match('/^172\.16.*/i', trim($_SERVER['REMOTE_ADDR'])) || preg_match('/^192\.168\.*/i', trim($_SERVER['REMOTE_ADDR'])) || preg_match('/^10\..*/i', trim($_SERVER['REMOTE_ADDR'])))) {
            if (strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ',')) {
                $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                return $ips[0];
            }
            else
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        return $_SERVER['REMOTE_ADDR'];
    }


}