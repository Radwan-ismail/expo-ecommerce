import { useAuth } from "@clerk/clerk-expo";
import axios from "axios";
import { useEffect } from "react";

// localhost will work in iOS simulator
// const API_URL = "http://localhost:3000/api";

// For Android emulator, use 10.0.2.2
// const API_URL = "http://10.0.2.2:3000/api";

// For physical device or different network
const API_URL = "http://192.168.100.3:3000/api";

// prod url will work in your physical device
// const API_URL = "https://expo-ecommerce-th4ln.sevalla.app/api"

const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

export const useApi = () => {
  const { getToken } = useAuth();

  useEffect(() => {
    const interceptor = api.interceptors.request.use(async (config) => {
      const token = await getToken();

      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }

      return config;
    });

    // cleanup: remove interceptor when component unmounts

    return () => {
      api.interceptors.request.eject(interceptor);
    };
  }, [getToken]);

  return api;
};

// on every single req, we would like have an auth token so that our backend knows that we're authenticated
// we're including the auth token under the auth headers
