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

        // Do we have IP in log? No need to call AbuseIPDB then. Just block'em.
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);
        $query->select('COUNT(*)');
        $query->from($db->quoteName('#__abuseipdb_entries'));
        $query->where($db->quoteName('message')." = ".$db->quote($IP),'AND');
        $query->where($db->quoteName('date')." > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ".$lookup_period." DAY) ");
        $db->setQuery($query);
        //Was it in log?
        if($db->loadResult()){
            //Logging it to database
            JLog::add($IP, JLog::INFO, 'abuseipdb_cache_blocked_ip');
            //Block'em
            header('HTTP/1.1 403 Forbidden');
            jexit();
        }

        //Not in log? lets look it up in AbuseIPDB
        $http = JHttpFactory::getHttp();
        $response = $http->get('https://www.abuseipdb.com/check/'.$IP.'/json?key='.$APIkey.'&days='.$lookup_period);
        // Did we get a connection?
        if($response->code == 200){
            //Converting JSON response body to array
            $abusearray = json_decode($response->body);
            //Count how many times the IP is registered
            $registered_attempts = count($abusearray);
            //Is it registered more times than we accepts?
            if($registered_attempts >= $min_attempts){
                //Logging it to database
                JLog::add($IP, JLog::INFO, 'abuseipdb_blocked_ip');
                //Block'em
                header('HTTP/1.1 403 Forbidden');
                jexit();
            }
        }
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