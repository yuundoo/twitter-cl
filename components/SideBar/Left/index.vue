import { LogoTwitter } from '#build/components';
<template>
   <div class="flex flex-col h-screen">
      <div class="p-2 my-2 hover:rounded-full hover:bg-blue-50 w-min dark:bg-white/20" :class="defaultTransition">
         <nuxt-link to="/">
            <div class="w-8 h-8">
               <LogoTwitter />
            </div>
         </nuxt-link>
      </div>
      <div class="mt-2 space-y-3">
         <SideBarLeftTab active>
            <template v-slot:icon>
               <HomeIcon />
            </template>
            <template v-slot:name> Home </template>
         </SideBarLeftTab>
         <SideBarLeftTab>
            <template v-slot:icon>
               <HashtagIcon />
            </template>
            <template v-slot:name> Explore </template>
         </SideBarLeftTab>

         <SideBarLeftTab>
            <template v-slot:icon>
               <BellIcon />
            </template>
            <template v-slot:name> Notification </template>
         </SideBarLeftTab>
         <SideBarLeftTab>
            <template v-slot:icon>
               <InboxIcon />
            </template>
            <template v-slot:name> Message </template>
         </SideBarLeftTab>
         <SideBarLeftTab>
            <template v-slot:icon>
               <BookmarkIcon />
            </template>
            <template v-slot:name> Bookmarks </template>
         </SideBarLeftTab>
         <SideBarLeftTab>
            <template v-slot:icon>
               <DocumentIcon />
            </template>
            <template v-slot:name> Lists </template>
         </SideBarLeftTab>
         <SideBarLeftTab>
            <template v-slot:icon>
               <UserIcon />
            </template>
            <template v-slot:name> Profile </template>
         </SideBarLeftTab>
         <SideBarLeftTab>
            <template v-slot:icon>
               <DotsHorizontalIcon />
            </template>
            <template v-slot:name> More </template>
         </SideBarLeftTab>
      </div>
   </div>
</template>

<script setup>
import { HomeIcon } from '@heroicons/vue/solid';
import {
   BellIcon,
   HashtagIcon,
   InboxIcon,
   BookmarkIcon,
   DocumentIcon,
   UserIcon,
   DotsHorizontalIcon,
} from '@heroicons/vue/outline';

const { defaultTransition } = useTailwindConfig();
</script>
