package com.dpi.util;

import com.dpi.model.AppType;

public class AppClassifier {
    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) return AppType.UNKNOWN;

        String s = sni.toLowerCase();

        // YouTube
        if (s.contains("youtube") || s.contains("ytimg") ||
            s.contains("youtu.be") || s.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }

        // Google
        if (s.contains("google") || s.contains("gstatic") ||
            s.contains("googleapis") || s.contains("ggpht") || s.contains("gvt1")) {
            return AppType.GOOGLE;
        }

        // Instagram
        if (s.contains("instagram") || s.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }

        // WhatsApp
        if (s.contains("whatsapp") || s.contains("wa.me")) {
            return AppType.WHATSAPP;
        }

        // Facebook/Meta
        if (s.contains("facebook") || s.contains("fbcdn") ||
            s.contains("fb.com") || s.contains("fbsbx") || s.contains("meta.com")) {
            return AppType.FACEBOOK;
        }

        // Twitter/X
        if (s.contains("twitter") || s.contains("twimg") ||
            s.contains("x.com") || s.contains("t.co")) {
            return AppType.TWITTER;
        }

        // Netflix
        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg")) {
            return AppType.NETFLIX;
        }

        // Amazon
        if (s.contains("amazon") || s.contains("amazonaws") ||
            s.contains("cloudfront") || s.contains("aws")) {
            return AppType.AMAZON;
        }

        // Microsoft
        if (s.contains("microsoft") || s.contains("msn.com") ||
            s.contains("office") || s.contains("azure") ||
            s.contains("live.com") || s.contains("outlook") || s.contains("bing")) {
            return AppType.MICROSOFT;
        }

        // Apple
        if (s.contains("apple") || s.contains("icloud") ||
            s.contains("mzstatic") || s.contains("itunes")) {
            return AppType.APPLE;
        }

        // Telegram
        if (s.contains("telegram") || s.contains("t.me")) {
            return AppType.TELEGRAM;
        }

        // TikTok
        if (s.contains("tiktok") || s.contains("tiktokcdn") ||
            s.contains("musical.ly") || s.contains("bytedance")) {
            return AppType.TIKTOK;
        }

        // Spotify
        if (s.contains("spotify") || s.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }

        // Zoom
        if (s.contains("zoom")) {
            return AppType.ZOOM;
        }

        // Discord
        if (s.contains("discord") || s.contains("discordapp")) {
            return AppType.DISCORD;
        }

        // GitHub
        if (s.contains("github") || s.contains("githubusercontent")) {
            return AppType.GITHUB;
        }

        // Cloudflare
        if (s.contains("cloudflare") || s.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }

        // Present but unmapped
        return AppType.HTTPS;
    }
}

