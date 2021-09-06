# Anguard
![alt tag](https://raw.githubusercontent.com/n0ise9914/anguard/master/misc/1.png)


### Unity3D
```C#
AndroidJavaClass unityPlayer = new AndroidJavaClass("com.unity3d.player.UnityPlayer");
AndroidJavaObject activity = unityPlayer.GetStatic<AndroidJavaObject>("currentActivity");
AndroidJavaObject context = activity.Call<AndroidJavaObject>("getApplicationContext");
AndroidJavaClass anguardClass = new AndroidJavaClass("com.anguard.Anguard");
anguardClass.CallStatic("initialize", context);
string token = anguardClass.CallStatic<string>("getToken", "");
```