<template>
   <div class="flex flex-col">
      <!-- Priview Card : What's happening -->
      <SideBarLeftRightPrivewCard title=" What's happening">
         <SideBarLeftRightPrivewCardItem v-for="whatsHappening in whatsHappening" :key="whatsHappening.id">
            <div>
               <h2 class="font-bold text-gray-800 text-md dark:text-white">{{ whatsHappening.title }}</h2>
               <p class="text-xs text-gray-400">
                  {{ whatsHappening.count }}
               </p>
            </div>
         </SideBarLeftRightPrivewCardItem>
      </SideBarLeftRightPrivewCard>
      <!-- Priview Card :Who to follow-->
      <SideBarLeftRightPrivewCard title=" Who to follow">
         <SideBarLeftRightPrivewCardItem v-for="whoToFollow in whoToFollow" :key="whoToFollow.id">
            <div class="flex flex-row justify-between p-2">
               <div class="flex flex-row">
                  <img class="w-10 h-10 rounded-full" :src="whoToFollow.image" :alt="whoToFollow.name" />
                  <div class="flex flex-col ml-2">
                     <h1 class="text-sm font-bold text-gray-900 dark:text-white">{{ whoToFollow.name }}</h1>
                     <p class="text-xs text-gray-400">{{ whoToFollow.handle }}</p>
                  </div>
               </div>
               <div class="flex h-full">
                  <button
                     class="px-4 py-2 text-xs font-bold text-white bg-black rounded-full dark:text-black dark:bg-white"
                  >
                     Follow
                  </button>
               </div>
            </div>
         </SideBarLeftRightPrivewCardItem>
      </SideBarLeftRightPrivewCard>
   </div>
</template>

<script setup>
const whatsHappening = ref([
   {
      title: 'SpaceX',
      count: '18.8K Tweets',
   },
   {
      title: '#Coding is Fun',
      count: '18.8K Tweets',
   },
   {
      title: '#Art for all',
      count: '18.8K Tweets',
   },
]);

const whoToFollow = ref([
   {
      name: 'Joe Biden',
      handle: '@joeBiden',
      image: 'https://picsum.photos/200/200',
   },
   {
      name: 'Joe Biden',
      handle: '@joeBiden',
      image: 'https://picsum.photos/200/200',
   },
   {
      name: 'Joe Biden',
      handle: '@joeBiden',
      image: 'https://picsum.photos/200/200',
   },
]);
</script>
