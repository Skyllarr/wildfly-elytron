package org.wildfly.security.http.oidc;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Encode {

    private static final String UTF_8 = StandardCharsets.UTF_8.name();
    private static final String[] pathEncoding = new String[128];
    private static final Pattern nonCodes = Pattern.compile("%([^a-fA-F0-9]|[a-fA-F0-9]$|$|[a-fA-F0-9][^a-fA-F0-9])");
    private static final Pattern PARAM_REPLACEMENT = Pattern.compile("_resteasy_uri_parameter");
    private static final String[] queryStringEncoding = new String[128];
    private static final String[] pathSegmentEncoding = new String[128];

    /**
     * @param zhar        integer representation of character
     * @param encodingMap encoding map
     * @return URL encoded character
     */
    private static String encode(int zhar, String[] encodingMap)
    {
        String encoded;
        if (zhar < encodingMap.length)
        {
            encoded = encodingMap[zhar];
        }
        else
        {
            try
            {
                encoded = URLEncoder.encode(Character.toString((char) zhar), UTF_8);
            }
            catch (UnsupportedEncodingException e)
            {
                throw new RuntimeException(e);
            }
        }
        return encoded;
    }

    public static String encodePath(String value)
    {
        return encodeValue(value, pathEncoding);
    }

    /**
     * Keep encoded values "%..." and template parameters intact i.e. "{x}"
     *
     * @param segment
     * @param encoding
     * @return
     */
    public static String encodeValue(String segment, String[] encoding)
    {
        ArrayList<String> params = new ArrayList<String>();
        boolean foundParam = false;
        StringBuilder newSegment = new StringBuilder();
        if (savePathParams(segment, newSegment, params))
        {
            foundParam = true;
            segment = newSegment.toString();
        }
        String result = encodeFromArray(segment, encoding, false);
        result = encodeNonCodes(result);
        segment = result;
        if (foundParam)
        {
            segment = pathParamReplacement(segment, params);
        }
        return segment;
    }

    public static String pathParamReplacement(String segment, List<String> params)
    {
        StringBuilder newSegment = new StringBuilder();
        Matcher matcher = PARAM_REPLACEMENT.matcher(segment);
        int i = 0;
        int start = 0;
        while (matcher.find())
        {
            newSegment.append(segment, start, matcher.start());
            String replacement = params.get(i++);
            newSegment.append(replacement);
            start = matcher.end();
        }
        newSegment.append(segment, start, segment.length());
        segment = newSegment.toString();
        return segment;
    }

    public static boolean savePathParams(String segment, StringBuilder newSegment, List<String> params)
    {
        boolean foundParam = false;
        // Regular expressions can have '{' and '}' characters.  Replace them to do match
        segment = PathHelper.replaceEnclosedCurlyBraces(segment);
        Matcher matcher = PathHelper.URI_TEMPLATE_PATTERN.matcher(segment);
        int start = 0;
        while (matcher.find())
        {
            newSegment.append(segment, start, matcher.start());
            foundParam = true;
            String group = matcher.group();
            // Regular expressions can have '{' and '}' characters.  Recover earlier replacement
            params.add(PathHelper.recoverEnclosedCurlyBraces(group));
            newSegment.append("_resteasy_uri_parameter");
            start = matcher.end();
        }
        newSegment.append(segment, start, segment.length());
        return foundParam;
    }

    protected static String encodeFromArray(String segment, String[] encodingMap, boolean encodePercent)
    {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < segment.length(); i++)
        {
            char currentChar = segment.charAt(i);
            if (!encodePercent && currentChar == '%')
            {
                result.append(currentChar);
                continue;
            }
            String encoding = encode(currentChar, encodingMap);
            if (encoding == null)
            {
                result.append(currentChar);
            }
            else
            {
                result.append(encoding);
            }
        }
        return result.toString();
    }

    /**
     * Encode '%' if it is not an encoding sequence
     *
     * @param string
     * @return
     */
    public static String encodeNonCodes(String string)
    {
        Matcher matcher = nonCodes.matcher(string);
        StringBuilder builder = new StringBuilder();


        // FYI: we do not use the no-arg matcher.find()
        //      coupled with matcher.appendReplacement()
        //      because the matched text may contain
        //      a second % and we must make sure we
        //      encode it (if necessary).
        int idx = 0;
        while (matcher.find(idx))
        {
            int start = matcher.start();
            builder.append(string.substring(idx, start));
            builder.append("%25");
            idx = start + 1;
        }
        builder.append(string.substring(idx));
        return builder.toString();
    }

    public static String encodeQueryString(String value)
    {
        return encodeValue(value, queryStringEncoding);
    }

    /**
     * Keep encoded values "%..." but not the template parameters.
     * @param value
     * @return
     */
    public static String encodeQueryStringNotTemplateParameters(String value) {
        return encodeNonCodes(encodeFromArray(value, queryStringEncoding, false));
    }

    public static String encodePathSegmentAsIs(String segment)
    {
        return encodeFromArray(segment, pathSegmentEncoding, true);
    }
}
